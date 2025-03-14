#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 3 - Verificación ==="

# Cargar variables de entorno
if [ -f .env ]; then
    export $(cat .env | xargs)
else
    echo "❌ Error: Archivo .env no encontrado"
    exit 1
fi

# Verificar Python y dependencias
echo "Verificando Python y dependencias..."
if python3 -c "import flask, flask_login, flask_sqlalchemy, psycopg2" 2>/dev/null; then
    echo "✅ Dependencias de Python instaladas correctamente"
else
    echo "❌ Error: Faltan dependencias de Python"
    exit 1
fi

# Verificar conexión a la base de datos
echo "Verificando conexión a la base de datos..."
if psql "$DATABASE_URL" -c '\q' 2>/dev/null; then
    echo "✅ Conexión a la base de datos exitosa"
else
    echo "❌ Error: No se puede conectar a la base de datos"
    exit 1
fi

# Verificar creación de tablas
echo "Verificando creación de tablas..."
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
"

if [ $? -eq 0 ]; then
    echo "✅ Tablas creadas correctamente"
else
    echo "❌ Error: No se pudieron crear las tablas"
    exit 1
fi

# Verificar que el puerto 5000 está disponible
echo "Verificando puerto 5000..."
if ! netstat -tuln | grep ":5000 " > /dev/null; then
    echo "✅ Puerto 5000 disponible"
else
    echo "❌ Error: Puerto 5000 en uso"
    exit 1
fi

echo "=== Verificación Completada ==="
echo "✅ La instalación se completó exitosamente"
echo ""
echo "Para iniciar la aplicación, ejecute:"
echo "source venv/bin/activate"
echo "gunicorn --bind 0.0.0.0:5000 app:app"
