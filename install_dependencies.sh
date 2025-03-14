#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 1 - Dependencias ==="
echo "Instalando dependencias del sistema y Python..."

# Actualizar el sistema
sudo apt-get update
sudo apt-get upgrade -y

# Instalar dependencias del sistema
sudo apt-get install -y python3.11 python3-pip postgresql postgresql-contrib libpq-dev

# Crear y activar entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias de Python
pip install flask==3.0.3 \
    flask-login==0.6.3 \
    flask-sqlalchemy==3.1.1 \
    gunicorn==23.0.0 \
    psycopg2-binary==2.9.10 \
    sqlalchemy==2.0.39 \
    email-validator==2.2.0 \
    flask-wtf==1.2.2 \
    pandas==2.2.3 \
    reportlab==4.3.1 \
    matplotlib==3.10.1 \
    flask-talisman==1.1.0 \
    pyopenssl==25.0.0

echo "✅ Dependencias instaladas correctamente"
echo "Para continuar con la instalación, ejecute: ./setup_database.sh"