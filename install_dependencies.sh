#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 1 - Dependencias ==="

# Verificar si pip está instalado
if ! command -v pip &> /dev/null; then
    echo "❌ Error: pip no está instalado"
    echo "Instalando pip..."
    sudo apt update
    sudo apt install -y python3-pip
fi

echo "Instalando dependencias de Python..."

# Instalar dependencias de Python
pip install --no-cache-dir \
    flask==3.0.3 \
    flask-login==0.6.3 \
    flask-sqlalchemy==3.1.1 \
    gunicorn==23.0.0 \
    psycopg2-binary==2.9.10 \
    sqlalchemy==2.0.39 \
    email-validator==2.2.0 \
    flask-wtf==1.2.1 \
    pandas==2.0.3 \
    reportlab==4.3.1 \
    matplotlib==3.7.5 \
    flask-talisman==1.1.0 \
    pyopenssl==25.0.0

if [ $? -ne 0 ]; then
    echo "❌ Error: Falló la instalación de dependencias"
    exit 1
fi

echo "✅ Dependencias instaladas correctamente"
echo "Para continuar con la instalación, ejecute: sudo ./setup_database.sh"