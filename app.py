import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True
}

# initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Make sure to import the models here or their tables won't be created
    import models  # noqa: F401
    db.create_all()

from flask import render_template, request, flash, redirect, url_for, send_from_directory, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import text
from werkzeug.utils import secure_filename
from database import init_db
from models import Sede, Escaneo, Host, Vulnerabilidad, User, ActivityLog
from exportar import exportar_a_csv, exportar_a_pdf
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicie sesión para acceder a esta página.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(action, details=None):
    """Log user activity"""
    if current_user.is_authenticated:
        activity = ActivityLog(
            user_id=current_user.id,
            action=action,
            details=details
        )
        db.session.add(activity)
        db.session.commit()

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_activity('login', f'Usuario {username} inició sesión')
            flash('Has iniciado sesión exitosamente', 'success')
            return redirect(url_for('dashboard'))

        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity('logout', f'Usuario {current_user.username} cerró sesión')
    logout_user()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))


# Configuración para subida de archivos
ALLOWED_EXTENSIONS = {'txt'}
UPLOAD_FOLDER = '/tmp'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def filtrar_resultados(sede=None, fecha_inicio=None, fecha_fin=None, riesgo=None):
    """Filtra los resultados según los criterios especificados"""
    query = Escaneo.query.join(Sede)

    if sede and sede != 'Todas las sedes':
        query = query.filter(Sede.nombre == sede)

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
                'sede': escaneo.sede.nombre,
                'fecha_escaneo': escaneo.fecha_escaneo.strftime('%Y-%m-%d'),
                'escaneo_id': escaneo.id,
                'hosts_detalle': hosts_detalle
            })

    return resultados

def obtener_sedes():
    """Obtiene la lista única de sedes activas que tienen escaneos"""
    # Query para obtener solo las sedes que tienen escaneos
    sql = text("""
        SELECT DISTINCT s.nombre
        FROM sedes s
        JOIN escaneos e ON e.sede_id = s.id
        WHERE s.activa = true
        ORDER BY s.nombre
    """)
    result = db.session.execute(sql)
    return [row[0] for row in result]

@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/configuracion')
@login_required
def configuracion():
    """Vista de configuración que incluye la gestión de sedes y escaneos"""
    sedes = Sede.query.order_by(Sede.nombre).all()
    sedes_activas = [s for s in sedes if s.activa]

    # Obtener todos los escaneos organizados por sede
    escaneos_por_sede = {}
    for sede in sedes:
        escaneos = Escaneo.query.filter_by(sede_id=sede.id)\
            .order_by(Escaneo.fecha_escaneo.desc())\
            .all()
        if escaneos:
            escaneos_por_sede[sede.nombre] = [
                {
                    'id': e.id,
                    'fecha': e.fecha_escaneo.strftime('%Y-%m-%d'),
                    'total_hosts': len(e.hosts),
                    'total_vulnerabilidades': sum(len(h.vulnerabilidades) for h in e.hosts)
                } for e in escaneos
            ]

    return render_template('configuracion.html', 
                         today=datetime.now().strftime('%Y-%m-%d'),
                         sedes=sedes,
                         sedes_activas=sedes_activas,
                         escaneos_por_sede=escaneos_por_sede)

@app.route('/dashboard')
@login_required
def dashboard():
    """Vista del dashboard principal"""
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    # Query base
    query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)

    # Aplicar filtros
    if sede:
        query = query.filter(Sede.nombre == sede)
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

@app.route('/hosts')
@login_required
def hosts():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    try:
        resultados_filtrados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)
        logger.debug(f"Resultados filtrados para hosts: {len(resultados_filtrados) if resultados_filtrados else 0} registros")

        return render_template('hosts.html', 
                            resultados=resultados_filtrados,
                            sedes=obtener_sedes(),
                            sede_seleccionada=sede,
                            fecha_inicio=fecha_inicio,
                            fecha_fin=fecha_fin,
                            riesgo=riesgo)
    except Exception as e:
        logger.error(f"Error en la vista de hosts: {str(e)}", exc_info=True)
        flash('Error al cargar la página de hosts', 'error')
        return render_template('hosts.html', 
                            resultados=[],
                            sedes=obtener_sedes(),
                            sede_seleccionada=sede,
                            fecha_inicio=fecha_inicio,
                            fecha_fin=fecha_fin,
                            riesgo=riesgo)

@app.route('/vulnerabilidades')
@login_required
def vulnerabilidades():
    try:
        sede = request.args.get('sede')
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')
        riesgo = request.args.get('riesgo')
        estado = request.args.get('estado')

        logger.debug(f"Filtros recibidos - sede: {sede}, fecha_inicio: {fecha_inicio}, fecha_fin: {fecha_fin}, riesgo: {riesgo}, estado: {estado}")

        query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)

        # Aplicar filtros
        if sede and sede != 'Todas las sedes':
            query = query.filter(Sede.nombre == sede)
        if fecha_inicio:
            query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
        if fecha_fin:
            query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())
        if riesgo and riesgo != 'all':
            query = query.filter(Vulnerabilidad.nivel_amenaza == riesgo)
        if estado and estado != 'all':
            query = query.filter(Vulnerabilidad.estado == estado)

        vulnerabilidades = query.all()
        logger.debug(f"Total de vulnerabilidades encontradas: {len(vulnerabilidades)}")

        return render_template('vulnerabilidades.html', 
                            resultados=vulnerabilidades,
                            sedes=obtener_sedes(),
                            sede_seleccionada=sede,
                            fecha_inicio=fecha_inicio,
                            fecha_fin=fecha_fin,
                            riesgo=riesgo,
                            estado=estado)

    except Exception as e:
        logger.error(f"Error en la vista de vulnerabilidades: {str(e)}", exc_info=True)
        flash('Error al cargar la página de vulnerabilidades', 'error')
        return render_template('vulnerabilidades.html',
                            resultados=[],
                            sedes=obtener_sedes(),
                            sede_seleccionada=sede if 'sede' in locals() else None,
                            fecha_inicio=fecha_inicio if 'fecha_inicio' in locals() else None,
                            fecha_fin=fecha_fin if 'fecha_fin' in locals() else None,
                            riesgo=riesgo if 'riesgo' in locals() else None,
                            estado=estado if 'estado' in locals() else None)

@app.route('/comparacion')
@login_required
def comparacion():
    """Vista de comparación de escaneos"""
    try:
        sede1 = request.args.get('sede1')
        sede2 = request.args.get('sede2')
        fecha1 = request.args.get('fecha1')
        fecha2 = request.args.get('fecha2')

        logger.debug(f"Parámetros recibidos: sede1={sede1}, fecha1={fecha1}, sede2={sede2}, fecha2={fecha2}")

        # Obtener todas las sedes disponibles
        sedes = obtener_sedes()
        logger.debug(f"Sedes disponibles: {sedes}")

        # Si no hay sedes seleccionadas y hay sedes disponibles, usar la primera
        if not sede1 and sedes:
            sede1 = sedes[0]
        if not sede2 and sedes:
            sede2 = sedes[0]

        # Obtener los escaneos de cada sede
        escaneos1 = []
        escaneos2 = []

        if sede1:
            sede1_obj = Sede.query.filter_by(nombre=sede1).first()
            if sede1_obj:
                escaneos1 = Escaneo.query.filter_by(sede_id=sede1_obj.id)\
                    .order_by(Escaneo.fecha_escaneo.desc()).all()

        if sede2:
            sede2_obj = Sede.query.filter_by(nombre=sede2).first()
            if sede2_obj:
                escaneos2 = Escaneo.query.filter_by(sede_id=sede2_obj.id)\
                    .order_by(Escaneo.fecha_escaneo.desc()).all()

        # Si no hay fechas seleccionadas, usar las más recientes
        if not fecha1 and escaneos1:
            fecha1 = escaneos1[0].fecha_escaneo.strftime('%Y-%m-%d')
        if not fecha2 and escaneos2:
            fecha2 = escaneos2[0].fecha_escaneo.strftime('%Y-%m-%d')

        resultados = None
        if fecha1 and fecha2 and sede1 and sede2:
            fecha1_obj = datetime.strptime(fecha1, '%Y-%m-%d').date()
            fecha2_obj = datetime.strptime(fecha2, '%Y-%m-%d').date()

            # Consulta SQL para obtener los conteos
            sql_query = text("""
            SELECT 
                s.nombre,
                e.fecha_escaneo,
                v.nivel_amenaza,
                COUNT(*) as total
            FROM escaneos e
            JOIN hosts h ON h.escaneo_id = e.id
            JOIN vulnerabilidades v ON v.host_id = h.id
            JOIN sedes s ON e.sede_id = s.id
            WHERE (s.nombre = :sede1 AND e.fecha_escaneo = :fecha1)
               OR (s.nombre = :sede2 AND e.fecha_escaneo = :fecha2)
            GROUP BY s.nombre, e.fecha_escaneo, v.nivel_amenaza
            ORDER BY e.fecha_escaneo, v.nivel_amenaza;
            """)

            result = db.session.execute(sql_query, {
                'sede1': sede1,
                'fecha1': fecha1_obj,
                'sede2': sede2,
                'fecha2': fecha2_obj
            })

            # Procesar resultados
            primer_conteo = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            segundo_conteo = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            primer_total = 0
            segundo_total = 0

            # Almacenar los resultados para procesarlos
            resultados_sql = list(result)
            logger.debug(f"Resultados SQL obtenidos: {resultados_sql}")

            # Si es el mismo escaneo, usar los mismos datos para ambos
            if sede1 == sede2 and fecha1_obj == fecha2_obj:
                for row in resultados_sql:
                    nivel_amenaza = row[2]
                    total = row[3]
                    primer_conteo[nivel_amenaza] = total
                    segundo_conteo[nivel_amenaza] = total
                    primer_total += total
                    segundo_total += total
            else:
                # Procesar normalmente para escaneos diferentes
                for row in resultados_sql:
                    sede = row[0]
                    fecha_escaneo = row[1]
                    nivel_amenaza = row[2]
                    total = row[3]

                    if sede == sede1 and fecha_escaneo == fecha1_obj:
                        primer_conteo[nivel_amenaza] = total
                        primer_total += total
                    elif sede == sede2 and fecha_escaneo == fecha2_obj:
                        segundo_conteo[nivel_amenaza] = total
                        segundo_total += total

            # Calcular variación
            variacion = segundo_total - primer_total
            porcentaje_variacion = (variacion / primer_total * 100) if primer_total > 0 else 0

            resultados = {
                'primer_escaneo': {
                    'fecha': fecha1,
                    'datos': primer_conteo,
                    'total': primer_total
                },
                'segundo_escaneo': {
                    'fecha': fecha2,
                    'datos': segundo_conteo,
                    'total': segundo_total
                },
                'variacion': {
                    'total': variacion,
                    'porcentaje': porcentaje_variacion
                }
            }

        return render_template('comparacion.html',
                            sedes=sedes,
                            sede1_seleccionada=sede1,
                            sede2_seleccionada=sede2,
                            escaneos1=escaneos1,
                            escaneos2=escaneos2,
                            fecha1=fecha1,
                            fecha2=fecha2,
                            resultados=resultados)

    except Exception as e:
        logger.error(f"Error en la vista de comparación: {str(e)}", exc_info=True)
        flash('Error al cargar la página de comparación', 'error')
        return redirect(url_for('dashboard'))

@app.route('/static/<path:filename>')
@login_required
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/tendencias')
@login_required
def obtener_tendencias():
    """Endpoint para obtener datos de tendencias de vulnerabilidades"""
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')

    logger.debug(f"Filtros recibidos - sede: {sede}, fecha_inicio: {fecha_inicio}, fecha_fin: {fecha_fin}")

    # Construir la consulta SQL base
    sql_base = """
        SELECT 
            e.fecha_escaneo,
            v.nivel_amenaza,
            COUNT(*) as total_vulnerabilidades
        FROM escaneos e
        JOIN hosts h ON h.escaneo_id = e.id
        JOIN vulnerabilidades v ON v.host_id = h.id
        JOIN sedes s ON e.sede_id = s.id
        WHERE 1=1
    """
    params = {}

    # Agregar condiciones según los filtros
    if sede and sede != 'Todas las sedes':
        sql_base += " AND s.nombre = :sede"
        params['sede'] = sede
    if fecha_inicio:
        sql_base += " AND e.fecha_escaneo >= :fecha_inicio"
        params['fecha_inicio'] = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
    if fecha_fin:
        sql_base += " AND e.fecha_escaneo <= :fecha_fin"
        params['fecha_fin'] = datetime.strptime(fecha_fin, '%Y-%m-%d').date()

    # Agregar agrupación y ordenamiento
    sql_base += " GROUP BY e.fecha_escaneo, v.nivel_amenaza ORDER BY e.fecha_escaneo, v.nivel_amenaza"

    logger.debug(f"SQL Query: {sql_base}")
    logger.debug(f"Params: {params}")

    # Ejecutar consulta
    result = db.session.execute(text(sql_base), params)

    # Procesar resultados
    tendencias = {}
    for row in result:
        fecha = row[0].strftime('%Y-%m-%d')
        nivel = row[1]
        total = row[2]

        if fecha not in tendencias:
            tendencias[fecha] = {
                'fecha': fecha,
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            }
        tendencias[fecha][nivel] = total

    logger.debug(f"Tendencias calculadas: {tendencias}")
    return jsonify(list(tendencias.values()))

@app.route('/actualizar_estado', methods=['POST'])
@login_required
def actualizar_estado():
    data = request.get_json()
    ip = data.get('ip')
    oid = data.get('oid')
    nuevo_estado = data.get('estado')

    if not all([ip, oid, nuevo_estado]):
        return jsonify({'success': False, 'error': 'Datos incompletos'}), 400

    try:
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
                log_activity('update_vulnerability_status', f'Actualizó el estado de la vulnerabilidad {oid} a {nuevo_estado}')
                return jsonify({'success': True})

        return jsonify({'success': False, 'error': 'Vulnerabilidad no encontrada'}), 404

    except Exception as e:
        logger.error(f"Error al actualizar estado: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/eliminar_escaneo/<int:escaneo_id>', methods=['POST'])
@login_required
def eliminar_escaneo(escaneo_id):
    """Elimina un escaneo y sus datos relacionados"""
    try:
        escaneo = Escaneo.query.get_or_404(escaneo_id)
        sede_nombre = escaneo.sede.nombre
        fecha = escaneo.fecha_escaneo.strftime('%Y-%m-%d')

        db.session.delete(escaneo)
        db.session.commit()
        log_activity('delete_scan', f'Eliminó el escaneo {escaneo_id} de la sede {sede_nombre}')
        flash(f'Escaneo de {sede_nombre} del {fecha} eliminado exitosamente', 'success')
    except Exception as e:
        logger.error(f"Error al eliminar escaneo: {str(e)}", exc_info=True)
        flash('Error al eliminar el escaneo', 'error')

    return redirect(url_for('configuracion'))

@app.route('/informes')
@login_required
def informes():
    """Vista de informes que permite generar diferentes tipos de reportes"""
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    # Query base para obtener estadísticas
    query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)

    # Aplicar filtros
    if sede:
        query = query.filter(Sede.nombre == sede)
    if fecha_inicio:
        query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
    if fecha_fin:
        query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())

    # Obtener todas las vulnerabilidades que cumplen los filtros
    vulnerabilidades = query.all()

    # Contar por criticidad
    criticidad = {
        'Critical': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Critical']),
        'High': len([v for v in vulnerabilidades if v.nivel_amenaza == 'High']),
        'Medium': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Medium']),
        'Low': len([v for v in vulnerabilidades if v.nivel_amenaza == 'Low'])
    }

    return render_template('informes.html',
                         criticidad=list(criticidad.values()),
                         sedes=obtener_sedes(),
                         sede_seleccionada=sede,
                         fecha_inicio=fecha_inicio,
                         fecha_fin=fecha_fin)

@app.route('/generar_informe/<tipo>/<formato>')
@login_required
def generar_informe(tipo, formato):
    """
    Genera un informe en el formato especificado
    tipo: 'ejecutivo' o 'tecnico'
    formato: 'pdf' o 'csv'
    """
    try:
        sede = request.args.get('sede')
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')
        riesgo = request.args.get('riesgo')

        logger.debug(f"Generando informe - Tipo: {tipo}, Formato: {formato}, Sede: {sede}")
        logger.debug(f"Fechas - Inicio: {fecha_inicio}, Fin: {fecha_fin}, Riesgo: {riesgo}")

        # Validar parámetros
        if tipo not in ['ejecutivo', 'tecnico']:
            flash('Tipo de informe no válido', 'error')
            return redirect(url_for('informes'))

        if formato not in ['pdf', 'csv']:
            flash('Formato de informe no válido', 'error')
            return redirect(url_for('informes'))

        # Obtener datos filtrados
        resultados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)
        logger.debug(f"Resultados obtenidos: {len(resultados)} registros")

        if not resultados:
            flash('No hay datos disponibles para generar el informe. Por favor, seleccione otros filtros.', 'warning')
            return redirect(url_for('informes'))

        # Preparar datos para el informe
        datos_informe = {
            'sede': sede,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'hosts_detalle': {}
        }

        for resultado in resultados:
            datos_informe['hosts_detalle'].update(resultado['hosts_detalle'])

        logger.debug(f"Datos preparados: {len(datos_informe['hosts_detalle'])} hosts")

        # Generar el informe según el tipo y formato
        try:
            if tipo == 'ejecutivo':
                from informes import generar_informe_ejecutivo
                logger.debug("Iniciando generación de informe ejecutivo")
                output = generar_informe_ejecutivo(datos_informe, tipo=formato)
                logger.debug("Informe ejecutivo generado exitosamente")
            else:  # técnico
                from informes import generar_informe_tecnico
                logger.debug("Iniciando generación de informe técnico")
                output = generar_informe_tecnico(datos_informe, tipo=formato)
                logger.debug("Informe técnico generado exitosamente")

            if not output:
                logger.error("La función de generación de informes retornó None")
                flash('Error al generar el informe. No se pudo crear el archivo.', 'error')
                return redirect(url_for('informes'))

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return send_file(
                output,
                mimetype='application/pdf' if formato == 'pdf' else 'text/csv',
                as_attachment=True,
                download_name=f'informe_{tipo}_{timestamp}.{formato}'
            )

        except Exception as e:
            logger.error(f"Error durante la generación del informe: {str(e)}", exc_info=True)
            raise

    except ImportError as e:
        logger.error(f"Error al importar módulo de informes: {str(e)}", exc_info=True)
        flash('Error interno: No se pudo cargar el generador de informes', 'error')
        return redirect(url_for('informes'))
    except Exception as e:
        logger.error(f"Error al generar informe: {str(e)}", exc_info=True)
        flash('Error al generar el informe. Por favor, inténtelo de nuevo.', 'error')
        return redirect(url_for('informes'))


@app.route('/exportar/<tipo>/<formato>')
@login_required
def exportar(tipo, formato):
    """
    Maneja la exportación de datos en diferentes formatos
    tipo: 'hosts' o 'vulnerabilidades'
    formato: 'csv' o 'pdf'
    """
    try:
        sede = request.args.get('sede')
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')
        riesgo = request.args.get('riesgo')

        if tipo not in ['hosts', 'vulnerabilidades']:
            flash('Tipo de exportación no válido', 'error')
            return redirect(url_for('dashboard'))

        if formato not in ['csv', 'pdf']:
            flash('Formato de exportación no válido', 'error')
            return redirect(url_for('dashboard'))

        # Obtener datos filtrados
        if tipo == 'hosts':
            resultados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)
            if not resultados:
                flash('No hay datosdisponibles para exportar', 'warning')
                return redirect(url_for('hosts'))
            if formato == 'csv':
                return exportar_a_csv(resultados, tipo_reporte='hosts')
            else:  # pdf
                return exportar_a_pdf(resultados, tipo_reporte='hosts')
        else:  # vulnerabilidades
            query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)
            if sede and sede != 'Todas las sedes':
                query = query.filter(Sede.nombre ==sede)
            if fecha_inicio:
                query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
            if fecha_fin:
                query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())
            if riesgo and riesgo != 'all':
                query = query.filter(Vulnerabilidad.nivel_amenaza == riesgo)

            vulnerabilidades = query.all()
            if not vulnerabilidades:
                flash('No haydatos disponibles para exportar', 'warning')
                return redirect(url_for('vulnerabilidades'))

            if formato == 'csv':                return exportar_a_csv(vulnerabilidades, tipo_reporte='vulnerabilidades')
            else:  # pdf
                return exportar_a_pdf(vulnerabilidades, tipo_reporte='vulnerabilidades')

    except Exception as e:
        logger.error(f"Error al exportar datos: {str(e)}", exc_info=True)
        flash('Error al exportar los datos', 'error')
        return redirect(url_for('dashboard'))

@app.route('/crear_sede', methods=['POST'])
@login_required
def crear_sede():
    """Crea una nueva sede"""
    try:
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion')

        if not nombre:
            flash('El nombre de la sede es requerido', 'error')
            return redirect(url_for('configuracion'))

        # Verificar si ya existe una sede con ese nombre
        sede_existente = Sede.query.filter_by(nombre=nombre).first()
        if sede_existente:
            flash('Ya existe una sede con ese nombre', 'error')
            return redirect(url_for('configuracion'))

        nueva_sede = Sede(
            nombre=nombre,
            descripcion=descripcion,
            activa=True
        )

        db.session.add(nueva_sede)
        db.session.commit()
        log_activity('create_sede', f'Creó la sede {nombre}')
        flash('Sede creada exitosamente', 'success')

    except Exception as e:
        logger.error(f"Error al crear sede: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al crear la sede', 'error')

    return redirect(url_for('configuracion'))

@app.route('/editar_sede/<int:sede_id>', methods=['POST'])
@login_required
def editar_sede(sede_id):
    """Edita una sede existente"""
    try:
        sede = Sede.query.get_or_404(sede_id)
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion')
        activa = request.form.get('activa') == 'true'

        if not nombre:
            flash('El nombre de la sede es requerido', 'error')
            return redirect(url_for('configuracion'))

        # Verificar si ya existe otra sede con ese nombre
        sede_existente = Sede.query.filter(
            Sede.nombre == nombre,
            Sede.id != sede_id
        ).first()

        if sede_existente:
            flash('Ya existe otra sede con ese nombre', 'error')
            return redirect(url_for('configuracion'))

        sede.nombre = nombre
        sede.descripcion = descripcion
        sede.activa = activa

        db.session.commit()
        log_activity('update_sede', f'Actualizó la sede {nombre}')
        flash('Sede actualizada exitosamente', 'success')

    except Exception as e:
        logger.error(f"Error al editar sede: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al editar la sede', 'error')

    return redirect(url_for('configuracion'))

@app.route('/eliminar_sede/<int:sede_id>', methods=['POST'])
@login_required
def eliminar_sede(sede_id):
    """Elimina una sede si no tiene escaneos asociados"""
    try:
        sede = Sede.query.get_or_404(sede_id)

        # Verificar si tiene escaneos
        if sede.escaneos:
            flash('No se puede eliminar la sede porque tiene escaneos asociados', 'error')
            return redirect(url_for('configuracion'))

        db.session.delete(sede)
        db.session.commit()
        log_activity('delete_sede', f'Eliminó la sede {sede.nombre}')
        flash('Sede eliminada exitosamente', 'success')

    except Exception as e:
        logger.error(f"Error al eliminar sede: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al eliminar la sede', 'error')

    return redirect(url_for('configuracion'))

@app.route('/subir_reporte', methods=['POST'])
@login_required
def subir_reporte():
    """Maneja la subida de un nuevo reporte de vulnerabilidades"""
    try:
        if 'archivo' not in request.files:
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('configuracion'))

        archivo = request.files['archivo']
        if archivo.filename == '':
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('configuracion'))

        if not allowed_file(archivo.filename):
            flash('Tipo de archivo no permitido. Solo se permiten archivos .txt', 'error')
            return redirect(url_for('configuracion'))

        # Obtener datos del formulario
        sede_id = request.form.get('sede_id')
        fecha_escaneo = request.form.get('fecha_escaneo')

        if not sede_id or not fecha_escaneo:
            flash('La sede y la fecha de escaneo son requeridas', 'error')
            return redirect(url_for('configuracion'))

        logger.debug(f"Iniciando procesamiento de archivo: {archivo.filename}")
        logger.debug(f"Sede ID: {sede_id}, Fecha escaneo: {fecha_escaneo}")

        # Guardar el archivo
        filename = secure_filename(archivo.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        archivo.save(filepath)

        # Procesar el archivo
        resultados = analizar_vulnerabilidades(filepath)
        if not resultados:
            logger.warning("No se encontraron vulnerabilidades en el archivo")
            flash('No se encontraron vulnerabilidades en el archivo', 'warning')
            os.remove(filepath)
            return redirect(url_for('configuracion'))

        logger.debug(f"Vulnerabilidades encontradas: {len(resultados.get('hosts_detalle', {}))}")

        # Crear el escaneo y sus relaciones
        fecha_escaneo_obj = datetime.strptime(fecha_escaneo, '%Y-%m-%d').date()
        nuevo_escaneo = Escaneo(
            sede_id=sede_id,
            fecha_escaneo=fecha_escaneo_obj
        )
        db.session.add(nuevo_escaneo)

        # Procesar cada host y sus vulnerabilidades
        for ip, host_data in resultados['hosts_detalle'].items():
            nuevo_host = Host(
                ip=ip,
                nombre_host=host_data.get('nombre_host', ''),
                escaneo=nuevo_escaneo
            )
            db.session.add(nuevo_host)

            for vuln_data in host_data.get('vulnerabilidades', []):
                nueva_vuln = Vulnerabilidad(
                    host=nuevo_host,
                    oid=vuln_data.get('oid', ''),
                    nvt=vuln_data.get('nvt', ''),
                    nivel_amenaza=vuln_data.get('nivel_amenaza', ''),
                    cvss=vuln_data.get('cvss', ''),
                    puerto=vuln_data.get('puerto', ''),
                    resumen=vuln_data.get('resumen', ''),
                    impacto=vuln_data.get('impacto', ''),
                    solucion=vuln_data.get('solucion', ''),
                    metodo_deteccion=vuln_data.get('metodo_deteccion', ''),
                    referencias=vuln_data.get('referencias', []),
                    estado='ACTIVA'
                )
                db.session.add(nueva_vuln)

        db.session.commit()
        log_activity('upload_report', f'Subió un reporte y creó {len(resultados.get("hosts_detalle", {}))} nuevos registros')
        logger.info("Reporte procesado exitosamente")
        flash('Reporte procesado exitosamente', 'success')

        # Eliminar el archivo temporal
        os.remove(filepath)
        return redirect(url_for('configuracion'))

    except Exception as e:
        logger.error(f"Error al procesar el reporte: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al procesar el reporte: ' + str(e), 'error')
        return redirect(url_for('configuracion'))

@app.route('/toggle_sede/<int:sede_id>', methods=['POST'])
@login_required
def toggle_sede(sede_id):
    """Activa o desactiva una sede"""
    try:
        sede = Sede.query.get_or_404(sede_id)
        sede.activa = not sede.activa
        db.session.commit()
        log_activity('toggle_sede', f'Cambió el estado de la sede {sede.nombre} a {"Activa" if sede.activa else "Inactiva"}')
        flash(f'Sede {sede.nombre} {"activada" if sede.activa else "desactivada"} exitosamente', 'success')
    except Exception as e:
        logger.error(f"Error al cambiar estado de sede: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al cambiar el estado de la sede', 'error')
    return redirect(url_for('configuracion'))

@app.route('/fechas_por_sede/<sede>')
@login_required
def fechas_por_sede(sede):
    """Obtiene las fechas disponibles para una sede específica"""
    try:
        query = db.session.query(Escaneo.fecha_escaneo)\
            .join(Sede)\
            .filter(Sede.activa == True)

        if sede != 'Todas las sedes':
            query = query.filter(Sede.nombre == sede)

        # Ordenar por fecha descendente y obtener fechas únicas
        fechas = query.order_by(Escaneo.fecha_escaneo.desc())\
            .distinct()\
            .all()

        # Formatear las fechas como strings YYYY-MM-DD
        fechas_formateadas = [fecha[0].strftime('%Y-%m-%d') for fecha in fechas]

        return jsonify(fechas_formateadas)
    except Exception as e:
        logger.error(f"Error al obtener fechas por sede: {str(e)}", exc_info=True)
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)