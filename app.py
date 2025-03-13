import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from parser import analizar_vulnerabilidades

# Configuración de logging más detallado
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SESSION_SECRET", "clave-secreta-desarrollo")

# Configuración para subida de archivos
ALLOWED_EXTENSIONS = {'txt'}
UPLOAD_FOLDER = '/tmp'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Almacenamiento temporal de resultados (en producción usar una base de datos)
resultados_analisis = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

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

        # Leer contenido del archivo para debugging
        with open(filepath, 'r', encoding='utf-8') as f:
            contenido = f.read()
            logger.debug(f"Contenido del archivo ({len(contenido)} caracteres):\n{contenido[:500]}...")

        # Analizar el archivo
        logger.debug("Iniciando análisis de vulnerabilidades")
        resultado = analizar_vulnerabilidades(filepath)
        logger.debug(f"Resultado del análisis: {resultado}")

        # Eliminar archivo temporal
        os.remove(filepath)

        if not resultado or 'hosts_detalle' not in resultado:
            logger.warning("No se encontraron vulnerabilidades en el análisis")
            flash('No se encontraron vulnerabilidades para analizar en el archivo', 'warning')
            return redirect(url_for('index'))

        # Agregar información adicional al resultado
        resultado['sede'] = sede
        resultado['fecha_escaneo'] = fecha_escaneo

        # Almacenar resultado
        resultados_analisis.append(resultado)

        logger.info(f"Análisis completado exitosamente para {filename}")
        return redirect(url_for('hosts'))

    except Exception as e:
        logger.error(f"Error al procesar el archivo: {str(e)}", exc_info=True)
        flash('Error al procesar el archivo. Por favor, inténtelo de nuevo.', 'error')
        return redirect(url_for('index'))

@app.route('/hosts')
def hosts():
    return render_template('hosts.html', resultados=resultados_analisis)

@app.route('/vulnerabilidades')
def vulnerabilidades():
    return render_template('vulnerabilidades.html', resultados=resultados_analisis)

@app.route('/comparativa')
def comparativa():
    return render_template('comparativa.html', resultados=resultados_analisis)