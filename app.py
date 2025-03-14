import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import text
from werkzeug.utils import secure_filename

# Set up logging with more detail
logging.basicConfig(
    level=logging.DEBUG if os.environ.get('FLASK_DEBUG') == '1' else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuración segura de la clave secreta
if not os.environ.get("SESSION_SECRET"):
    logger.warning("SESSION_SECRET not set! Using a random secret key.")
    app.secret_key = os.urandom(24)
else:
    app.secret_key = os.environ.get("SESSION_SECRET")

# Initialize database
from database import db, init_db
init_db(app)

# Import models after database initialization
from models import User, Sede, Escaneo, Host, Vulnerabilidad, ActivityLog

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicie sesión para acceder a esta página.'
login_manager.login_message_category = 'warning'

def create_default_admin():
    """Create default admin user if it doesn't exist"""
    try:
        # Importante: Verificar si ya existe el usuario admin
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            logger.info("Creating default admin user...")
            admin = User(
                username='admin',
                email='admin@sectracker.local',
                is_admin=True,
                role='admin',
                is_active=True,
                created_at=datetime.utcnow()
            )
            admin.set_password('SecTracker2024!')
            db.session.add(admin)
            db.session.commit()
            logger.info("✅ Default admin user created successfully")
            logger.info("Username: admin")
            logger.info("Password: SecTracker2024!")
        else:
            logger.info("Default admin user already exists")
    except Exception as e:
        logger.error(f"Error creating default admin user: {str(e)}")
        db.session.rollback()

# Initialize database and create admin user
with app.app_context():
    db.create_all()
    create_default_admin()


@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.get(int(user_id))
        if user:
            logger.debug(f"Successfully loaded user {user_id}")
            return user
        logger.warning(f"No user found with id {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login with detailed error logging"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if not username or not password:
                logger.warning("Login attempt with missing credentials")
                flash('Por favor ingrese usuario y contraseña', 'error')
                return render_template('login.html')

            logger.debug(f"Login attempt for user: {username}")
            user = User.query.filter_by(username=username).first()

            if not user:
                logger.warning(f"Login attempt failed: User {username} not found")
                flash('Usuario o contraseña incorrectos', 'error')
                return render_template('login.html')

            if not user.is_active:
                logger.warning(f"Login attempt failed: User {username} is inactive")
                flash('Esta cuenta está desactivada', 'error')
                return render_template('login.html')

            if user.check_password(password):
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                logger.info(f"User {username} logged in successfully")
                flash('Has iniciado sesión exitosamente', 'success')
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Login attempt failed: Invalid password for user {username}")
                flash('Usuario o contraseña incorrectos', 'error')

        return render_template('login.html')

    except Exception as e:
        logger.exception("Error en el proceso de login")
        db.session.rollback()
        flash('Error interno del servidor. Por favor, inténtelo de nuevo.', 'error')
        return render_template('login.html'), 500

def log_activity(action, details=None):
    """Log user activity"""
    try:
        if current_user.is_authenticated:
            activity = ActivityLog(
                user_id=current_user.id,
                action=action,
                details=details
            )
            db.session.add(activity)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error logging activity: {str(e)}")
        db.session.rollback()

@app.route('/logout')
@login_required
def logout():
    try:
        username = current_user.username
        log_activity('logout', f'Usuario {username} cerró sesión')
        logout_user()
        flash('Has cerrado sesión exitosamente', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception("Error during logout")
        flash('Error al cerrar sesión', 'error')
        return redirect(url_for('login'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

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

@app.route('/configuracion')
@login_required
def configuracion():
    """Vista de configuración que incluye la gestión de sedes y escaneos"""
    sedes = Sede.query.order_by(Sede.nombre).all()
    sedes_activas = [s for s in sedes if s.activa]
    usuarios = User.query.all()  # Agregamos la consulta de usuarios

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
                         escaneos_por_sede=escaneos_por_sede,
                         usuarios=usuarios)  # Agregamos los usuarios al contexto

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
                flash('No hay datos disponibles para exportar', 'warning')
                return redirect(url_for('hosts'))
            if formato == 'csv':
                return exportar_a_csv(resultados, tipo_reporte='hosts')
            else:  # pdf
                return exportar_a_pdf(resultados, tipo_reporte='hosts')
        else:  # vulnerabilidades
            query = Vulnerabilidad.query.join(Host).join(Escaneo).join(Sede)
            if sede and sede != 'Todas las sedes':
                query = query.filter(Sede.nombre == sede)
            if fecha_inicio:
                query = query.filter(Escaneo.fecha_escaneo >= datetime.strptime(fecha_inicio, '%Y-%m-%d').date())
            if fecha_fin:
                query = query.filter(Escaneo.fecha_escaneo <= datetime.strptime(fecha_fin, '%Y-%m-%d').date())
            if riesgo and riesgo != 'all':
                query = query.filter(Vulnerabilidad.nivel_amenaza == riesgo)

            vulnerabilidades = query.all()
            if not vulnerabilidades:
                flash('No hay datos disponibles para exportar', 'warning')
                return redirect(url_for('vulnerabilidades'))

            if formato == 'csv':
                return exportar_a_csv(vulnerabilidades, tipo_reporte='vulnerabilidades')
            else:  # pdf
                return exportar_a_pdf(vulnerabilidades, tipo_reporte='vulnerabilidades')

    except Exception as e:
        logger.error(f"Error al exportar datos: {str(e)}")
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
    """
    Maneja la subida y procesamiento de reportes de vulnerabilidades
    """
    try:
        logger.debug("Iniciando procesamiento de archivo")
        logger.debug(f"Formulario recibido: {request.form}")
        logger.debug(f"Archivos recibidos: {request.files}")

        if 'archivo' not in request.files:
            logger.error("No se encontró el archivo en la solicitud")
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('configuracion'))

        archivo = request.files['archivo']
        sede_id = request.form.get('sede_id')  # Cambiado de 'sede' a 'sede_id'
        fecha_escaneo = request.form.get('fecha_escaneo')

        logger.debug(f"Sede ID: {sede_id}, Fecha escaneo: {fecha_escaneo}")
        logger.debug(f"Nombre del archivo: {archivo.filename}")

        if archivo.filename == '':
            logger.error("Nombre de archivo vacío")
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('configuracion'))

        if not sede_id:
            logger.error("No se seleccionó una sede")
            flash('Debe seleccionar una sede', 'error')
            return redirect(url_for('configuracion'))

        if not allowed_file(archivo.filename):
            logger.error(f"Tipo de archivo no permitido: {archivo.filename}")
            flash('Tipo de archivo no permitido. Solo se permiten archivos .txt', 'error')
            return redirect(url_for('configuracion'))

        try:
            filename = secure_filename(archivo.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            archivo.save(filepath)
            logger.debug(f"Archivo guardado en: {filepath}")

            # Procesar el reporte
            logger.debug("Iniciando análisis de vulnerabilidades")
            resultados = analizar_vulnerabilidades(filepath)
            logger.debug(f"Resultados del análisis: {resultados is not None}")

            if not resultados:
                logger.error("No se encontraron resultados al analizar el archivo")
                flash('No se encontraron vulnerabilidades en el archivo', 'warning')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(url_for('configuracion'))

            try:
                # Crear el escaneo
                escaneo = Escaneo(
                    sede_id=sede_id,
                    fecha_escaneo=datetime.strptime(fecha_escaneo, '%Y-%m-%d').date()
                )
                db.session.add(escaneo)
                db.session.flush()
                logger.debug(f"Escaneo creado con ID: {escaneo.id}")

                # Procesar cada host y sus vulnerabilidades
                total_hosts = 0
                total_vulns = 0
                for ip, host_data in resultados['hosts_detalle'].items():
                    logger.debug(f"Procesando host: {ip}")
                    host = Host(
                        ip=ip,
                        nombre_host=host_data.get('nombre_host', ''),
                        escaneo_id=escaneo.id
                    )
                    db.session.add(host)
                    db.session.flush()
                    total_hosts += 1

                    for vuln_data in host_data.get('vulnerabilidades', []):
                        vulnerabilidad = Vulnerabilidad(
                            host_id=host.id,
                            nvt=vuln_data.get('nvt', ''),
                            oid=vuln_data.get('oid', ''),
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
                        db.session.add(vulnerabilidad)
                        total_vulns += 1

                db.session.commit()
                logger.info(f"Datos guardados exitosamente: {total_hosts} hosts, {total_vulns} vulnerabilidades")
                log_activity('upload_report', f'Subió reporte para sede ID {sede_id}: {total_hosts} hosts, {total_vulns} vulnerabilidades')
                flash('Reporte procesado exitosamente', 'success')

            except Exception as db_error:
                logger.error(f"Error al guardar en la base de datos: {str(db_error)}", exc_info=True)
                db.session.rollback()
                flash('Error al guardar los datos en la base de datos', 'error')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(url_for('configuracion'))

            # Limpiar el archivo temporal
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.debug("Archivo temporal eliminado")

            return redirect(url_for('configuracion'))

        except Exception as file_error:
            logger.error(f"Error al procesar el archivo: {str(file_error)}", exc_info=True)
            if os.path.exists(filepath):
                os.remove(filepath)
            flash('Error al procesar el archivo', 'error')
            return redirect(url_for('configuracion'))

    except Exception as e:
        logger.error(f"Error general al procesar el reporte: {str(e)}", exc_info=True)
        flash('Error al procesar el reporte', 'error')
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

@app.route('/crear_usuario', methods=['POST'])
@login_required
def crear_usuario():
    """Crea un nuevo usuario"""
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([username, email, password]):
            flash('Todos los campos son requeridos', 'error')
            return redirect(url_for('configuracion'))

        # Verificar si ya existe un usuario con ese nombre o email
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Ya existe un usuario con ese nombre de usuario o correo electrónico', 'error')
            return redirect(url_for('configuracion'))

        nuevo_usuario = User(
            username=username,
            email=email,
            is_active=True
        )
        nuevo_usuario.set_password(password)

        db.session.add(nuevo_usuario)
        db.session.commit()
        log_activity('create_user', f'Creó el usuario {username}')
        flash('Usuario creado exitosamente', 'success')

    except Exception as e:
        logger.error(f"Error al crear usuario: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al crear el usuario', 'error')

    return redirect(url_for('configuracion'))

@app.route('/toggle_usuario/<int:user_id>', methods=['POST'])
@login_required
def toggle_usuario(user_id):
    """Activa/desactiva un usuario"""
    try:
        usuario = User.query.get_or_404(user_id)
        usuario.is_active = not usuario.is_active
        db.session.commit()
        log_activity('toggle_user', f'Cambió el estado del usuario {usuario.username} a {"activo" if usuario.is_active else "inactivo"}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error al cambiar estado de usuario: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/eliminar_usuario/<int:user_id>', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    """Elimina un usuario del sistema"""
    try:
        usuario = User.query.get_or_404(user_id)

        # No permitir eliminar al usuario admin
        if usuario.username == 'admin':
            flash('No se puede eliminar el usuario administrador', 'error')
            return redirect(url_for('configuracion'))

        # Guardar el username para el log
        username = usuario.username

        # Eliminar el usuario
        db.session.delete(usuario)
        db.session.commit()

        log_activity('delete_user', f'Eliminó el usuario {username}')
        flash('Usuario eliminado exitosamente', 'success')

        # Si el usuario eliminó su propia cuenta, cerrar sesión
        if current_user.id == user_id:
            logout_user()
            return redirect(url_for('login'))

        return redirect(url_for('configuracion'))

    except Exception as e:
        logger.error(f"Error al eliminar usuario: {str(e)}", exc_info=True)
        db.session.rollback()
        flash('Error al eliminar el usuario', 'error')
        return redirect(url_for('configuracion'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ALLOWED_EXTENSIONS = {'txt'}
UPLOAD_FOLDER = '/tmp'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limitar subidas a 16MB

def analizar_vulnerabilidades(filepath):
    """Analiza el archivo de reporte de vulnerabilidades"""
    try:
        from parser import analizar_vulnerabilidades as parser_analizar
        return parser_analizar(filepath)
    except Exception as e:
        logger.error(f"Error al analizar vulnerabilidades: {str(e)}")
        raise


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)