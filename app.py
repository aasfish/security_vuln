import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.utils import secure_filename
from parser import analizar_vulnerabilidades

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
# initialize the app with the extension, flask-sqlalchemy >= 3.0.x
db.init_app(app)

with app.app_context():
    # Make sure to import the models here or their tables won't be created
    import models  # noqa: F401

    db.create_all()

# Configuración para subida de archivos
ALLOWED_EXTENSIONS = {'txt'}
UPLOAD_FOLDER = '/tmp'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def filtrar_resultados(sede=None, fecha_inicio=None, fecha_fin=None, riesgo=None):
    """Filtra los resultados según los criterios especificados"""
    from models import Escaneo, Host, Vulnerabilidad

    query = Escaneo.query

    if sede and sede != 'Todas las sedes':
        query = query.filter(Escaneo.sede == sede)

    if fecha_inicio:
        fecha_inicio_obj = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        query = query.filter(Escaneo.fecha_escaneo >= fecha_inicio_obj)

    if fecha_fin:
        fecha_fin_obj = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
        query = query.filter(Escaneo.fecha_escaneo <= fecha_fin_obj)

    # Ordenar por fecha de escaneo descendente (más reciente primero)
    escaneos = query.order_by(Escaneo.fecha_escaneo.desc()).all()
    resultados = []

    for escaneo in escaneos:
        hosts_detalle = {}
        for host in escaneo.hosts:
            vulns = host.vulnerabilidades
            if riesgo and riesgo != 'all':
                vulns = [v for v in vulns if v.nivel_amenaza == riesgo]
                if not vulns:
                    continue

            hosts_detalle[host.ip] = {
                'nombre_host': host.nombre_host,
                'vulnerabilidades': [{
                    'nvt': v.nvt,
                    'oid': v.oid,
                    'nivel_amenaza': v.nivel_amenaza,
                    'cvss': v.cvss,
                    'puerto': v.puerto,
                    'resumen': v.resumen,
                    'impacto': v.impacto,
                    'solucion': v.solucion,
                    'metodo_deteccion': v.metodo_deteccion,
                    'referencias': v.referencias,
                    'estado': v.estado
                } for v in vulns]
            }

        if hosts_detalle:
            resultados.append({
                'sede': escaneo.sede,
                'fecha_escaneo': escaneo.fecha_escaneo.strftime('%Y-%m-%d'),
                'hosts_detalle': hosts_detalle
            })

    return resultados

def obtener_sedes():
    """Obtiene la lista única de sedes de los resultados"""
    from models import Escaneo
    return sorted(list(set(r.sede for r in Escaneo.query.all())))

@app.route('/')
def index():
    return render_template('index.html', today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/analizar', methods=['POST'])
def analizar():
    if 'archivo' not in request.files:
        logger.error("No se encontró archivo en la solicitud")
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('index'))

    archivo = request.files['archivo']
    sede = request.form.get('sede', '')
    fecha_escaneo = request.form.get('fecha_escaneo', datetime.now().strftime('%Y-%m-%d'))

    if archivo.filename == '':
        logger.error("Nombre de archivo vacío")
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('index'))

    if not allowed_file(archivo.filename):
        logger.error(f"Tipo de archivo no permitido: {archivo.filename}")
        flash('Tipo de archivo no permitido. Solo se aceptan archivos .txt', 'error')
        return redirect(url_for('index'))

    try:
        filename = secure_filename(archivo.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        archivo.save(filepath)
        logger.debug(f"Archivo guardado en: {filepath}")

        resultado = analizar_vulnerabilidades(filepath)
        os.remove(filepath)

        if not resultado or 'hosts_detalle' not in resultado:
            logger.warning("No se encontraron vulnerabilidades en el análisis")
            flash('No se encontraron vulnerabilidades para analizar en el archivo', 'warning')
            return redirect(url_for('index'))

        # Crear nuevo escaneo en la base de datos
        from models import Escaneo, Host, Vulnerabilidad

        escaneo = Escaneo(
            sede=sede,
            fecha_escaneo=datetime.strptime(fecha_escaneo, '%Y-%m-%d').date()
        )
        db.session.add(escaneo)

        for ip, host_data in resultado['hosts_detalle'].items():
            host = Host(
                ip=ip,
                nombre_host=host_data['nombre_host'],
                escaneo=escaneo
            )
            db.session.add(host)

            for vuln_data in host_data['vulnerabilidades']:
                vulnerabilidad = Vulnerabilidad(
                    oid=vuln_data['oid'],
                    nvt=vuln_data['nvt'],
                    nivel_amenaza=vuln_data['nivel_amenaza'],
                    cvss=vuln_data['cvss'],
                    puerto=vuln_data['puerto'],
                    resumen=vuln_data['resumen'],
                    impacto=vuln_data['impacto'],
                    solucion=vuln_data['solucion'],
                    metodo_deteccion=vuln_data['metodo_deteccion'],
                    referencias=vuln_data['referencias'],
                    estado='ACTIVA',
                    host=host
                )
                db.session.add(vulnerabilidad)

        db.session.commit()
        logger.info(f"Análisis completado exitosamente para {filename}")
        return redirect(url_for('hosts'))

    except Exception as e:
        logger.error(f"Error al procesar el archivo: {str(e)}", exc_info=True)
        flash('Error al procesar el archivo. Por favor, inténtelo de nuevo.', 'error')
        return redirect(url_for('index'))

@app.route('/actualizar_estado', methods=['POST'])
def actualizar_estado():
    data = request.get_json()
    ip = data.get('ip')
    oid = data.get('oid')
    nuevo_estado = data.get('estado')

    if not all([ip, oid, nuevo_estado]):
        return jsonify({'success': False, 'error': 'Datos incompletos'}), 400

    try:
        from models import Host, Vulnerabilidad

        # Buscar la vulnerabilidad por IP y OID
        host = Host.query.filter_by(ip=ip).first()
        if host:
            vulnerabilidad = Vulnerabilidad.query.filter_by(
                host_id=host.id,
                oid=oid
            ).first()

            if vulnerabilidad:
                vulnerabilidad.estado = nuevo_estado
                db.session.commit()
                return jsonify({'success': True})

        return jsonify({'success': False, 'error': 'Vulnerabilidad no encontrada'}), 404

    except Exception as e:
        logger.error(f"Error al actualizar estado: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/hosts')
def hosts():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    resultados_filtrados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)

    return render_template('hosts.html', 
                         resultados=resultados_filtrados,
                         sedes=obtener_sedes(),
                         sede_seleccionada=sede,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin)

@app.route('/vulnerabilidades')
def vulnerabilidades():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')
    estado = request.args.get('estado')  # Nuevo parámetro para filtrar por estado

    from models import Escaneo, Host, Vulnerabilidad
    query = Vulnerabilidad.query.join(Host).join(Escaneo)

    # Aplicar filtros existentes
    if sede:
        query = query.filter(Escaneo.sede == sede)
    if fecha_inicio:
        query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
    if fecha_fin:
        query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())
    if riesgo:
        query = query.filter(Vulnerabilidad.nivel_amenaza == riesgo)
    if estado:
        query = query.filter(Vulnerabilidad.estado == estado)

    vulnerabilidades = query.all()

    return render_template('vulnerabilidades.html', 
                         resultados=vulnerabilidades,
                         sedes=obtener_sedes(),
                         sede_seleccionada=sede,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin,
                         estado=estado)

@app.route('/comparativa')
def comparativa():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    resultados_filtrados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)

    return render_template('comparativa.html', 
                         resultados=resultados_filtrados,
                         sedes=obtener_sedes(),
                         sede_seleccionada=sede,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/fechas_por_sede/<sede>')
def fechas_por_sede(sede):
    """Obtiene las fechas disponibles para una sede específica"""
    from models import Escaneo
    query = Escaneo.query

    if sede != 'Todas las sedes':
        query = query.filter(Escaneo.sede == sede)

    fechas = query.with_entities(Escaneo.fecha_escaneo)\
        .distinct()\
        .order_by(Escaneo.fecha_escaneo.desc())\
        .all()

    return jsonify([fecha[0].strftime('%Y-%m-%d') for fecha in fechas])

@app.route('/dashboard')
def dashboard():
    """Vista del dashboard principal"""
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    from models import Escaneo, Host, Vulnerabilidad

    # Query base
    query = Vulnerabilidad.query.join(Host).join(Escaneo)

    # Aplicar filtros
    if sede:
        query = query.filter(Escaneo.sede == sede)
    if fecha_inicio:
        query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
    if fecha_fin:
        query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())

    # Obtener todas las vulnerabilidades que cumplen los filtros
    vulnerabilidades = query.all()
    total_vulnerabilidades = len(vulnerabilidades)

    # Calcular riesgo promedio (CVSS)
    vulnerabilidades_con_cvss = [v for v in vulnerabilidades if v.cvss and v.cvss.replace('.','').isdigit()]
    if vulnerabilidades_con_cvss:
        riesgo_total = sum(float(v.cvss) for v in vulnerabilidades_con_cvss)
        riesgo_promedio = round(riesgo_total / len(vulnerabilidades_con_cvss), 1)
    else:
        riesgo_promedio = 0.0

    # Contar estados
    estados = {
        'mitigada': len([v for v in vulnerabilidades if v.estado == 'MITIGADA']),
        'asumida': len([v for v in vulnerabilidades if v.estado == 'ASUMIDA']),
        'vigente': len([v for v in vulnerabilidades if v.estado == 'ACTIVA'])
    }

    # Contar por criticidad
    criticidad = {
        'Critical': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Critical']),
        'High': len([v for v in vulnerabilidades if v.nivel_amenaza == 'High']),
        'Medium': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Medium']),
        'Low': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Low'])
    }

    return render_template('dashboard.html',
                         riesgo_promedio=riesgo_promedio,
                         total_vulnerabilidades=total_vulnerabilidades,
                         estados=estados,
                         criticidad=list(criticidad.values()),
                         sedes=obtener_sedes(),
                         sede_seleccionada=sede,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin)

@app.route('/configuracion')
def configuracion():
    """Vista de configuración que incluye la carga de archivos"""
    return render_template('configuracion.html', today=datetime.now().strftime('%Y-%m-%d'))