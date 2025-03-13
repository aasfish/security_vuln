from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory, jsonify, send_file
from sqlalchemy import text
from werkzeug.utils import secure_filename
from parser import analizar_vulnerabilidades
from database import db, init_db
from models import Sede, Escaneo, Host, Vulnerabilidad
from exportar import exportar_a_csv, exportar_a_pdf
import logging
import os
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# initialize the database
init_db(app)

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

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
def index():
    return redirect(url_for('dashboard'))

@app.route('/configuracion')
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
def hosts():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')

    try:
        resultados_filtrados = filtrar_resultados(sede, fecha_inicio, fecha_fin, riesgo)
        logger.debug(f"Resultados filtrados para hosts: {len(resultados_filtrados)} registros")

        return render_template('hosts.html', 
                            resultados=resultados_filtrados,
                            sedes=obtener_sedes(),
                            sede_seleccionada=sede,
                            fecha_inicio=fecha_inicio,
                            fecha_fin=fecha_fin)
    except Exception as e:
        logger.error(f"Error en la vista de hosts: {str(e)}", exc_info=True)
        flash('Error al cargar la página de hosts', 'error')
        return redirect(url_for('dashboard'))

@app.route('/vulnerabilidades')
def vulnerabilidades():
    sede = request.args.get('sede')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    riesgo = request.args.get('riesgo')
    estado = request.args.get('estado')  # Nuevo parámetro para filtrar por estado

    query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)

    # Aplicar filtros existentes
    if sede:
        query = query.filter(Sede.nombre == sede)
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

@app.route('/comparacion')
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
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/tendencias')
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
                return jsonify({'success': True})

        return jsonify({'success': False, 'error': 'Vulnerabilidad no encontrada'}), 404

    except Exception as e:
        logger.error(f"Error al actualizar estado: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/eliminar_escaneo/<int:escaneo_id>', methods=['POST'])
def eliminar_escaneo(escaneo_id):
    """Elimina un escaneo y sus datos relacionados"""
    try:
        escaneo = Escaneo.query.get_or_404(escaneo_id)
        sede_nombre = escaneo.sede.nombre
        fecha = escaneo.fecha_escaneo.strftime('%Y-%m-%d')

        db.session.delete(escaneo)
        db.session.commit()

        flash(f'Escaneo de {sede_nombre} del {fecha} eliminado exitosamente', 'success')
    except Exception as e:
        logger.error(f"Error al eliminar escaneo: {str(e)}", exc_info=True)
        flash('Error al eliminar el escaneo', 'error')

    return redirect(url_for('configuracion'))

@app.route('/informes')
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)