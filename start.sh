#!/bin/bash

# Cargar variables de entorno
if [ -f .env ]; then
    set -a
    source .env
    set +a
else
    echo "❌ Error: Archivo .env no encontrado"
    exit 1
fi

# Verificar variable DATABASE_URL
if [ -z "$DATABASE_URL" ]; then
    echo "❌ Error: DATABASE_URL no está configurada"
    exit 1
fi

# Iniciar la aplicación con gunicorn
exec gunicorn --bind 0.0.0.0:5000 app:app
