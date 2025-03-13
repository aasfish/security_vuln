import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from parser import analizar_vulnerabilidades

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SESSION_SECRET", "clave-secreta-desarrollo")

# Configuración para subida de archivos
ALLOWED_EXTENSIONS = {'txt'}
UPLOAD_FOLDER = '/tmp'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Almacenamiento en memoria de resultados
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
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('index'))

    archivo = request.files['archivo']

    if archivo.filename == '':
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(url_for('index'))

    if not allowed_file(archivo.filename):
        flash('Tipo de archivo no permitido. Solo se aceptan archivos .txt', 'error')
        return redirect(url_for('index'))

    try:
        filename = secure_filename(archivo.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        archivo.save(filepath)

        # Analizar el archivo
        resultado = analizar_vulnerabilidades(filepath)

        # Almacenar resultado
        resultados_analisis.append(resultado)

        # Eliminar archivo temporal
        os.remove(filepath)

        return render_template('resultados.html', 
                             resultado=resultado,
                             nombre_archivo=filename)

    except Exception as e:
        logging.error(f"Error al procesar el archivo: {str(e)}")
        flash('Error al procesar el archivo. Por favor, inténtelo de nuevo.', 'error')
        return redirect(url_for('index'))