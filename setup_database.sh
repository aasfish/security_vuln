#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 2 - Instalación y Configuración de Base de Datos ==="

# Verificar si PostgreSQL está instalado
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL no está instalado. Instalando..."
    # Agregar el repositorio PostgreSQL
    sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

    # Actualizar e instalar PostgreSQL
    sudo apt-get update
    sudo apt-get install -y postgresql postgresql-contrib libpq-dev

    if [ $? -ne 0 ]; then
        echo "❌ Error: Falló la instalación de PostgreSQL"
        exit 1
    fi

    echo "PostgreSQL instalado correctamente"
else
    echo "PostgreSQL ya está instalado"
fi

# Iniciar PostgreSQL si no está corriendo
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Definir variables de la base de datos
DB_NAME="sectracker"
DB_USER="sectracker_user"
DB_PASSWORD="SecTracker2024!"
DB_HOST="localhost"
DB_PORT="5432"

# Crear usuario y base de datos
sudo -u postgres psql <<EOF
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
CREATE DATABASE $DB_NAME WITH OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
\c $DB_NAME
GRANT ALL ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
EOF

if [ $? -ne 0 ]; then
    echo "❌ Error: Falló la creación de la base de datos"
    exit 1
fi

# Crear archivo .env con las variables de entorno
cat > .env << EOF
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
SESSION_SECRET="tu_clave_secreta_aqui_cambiame_en_produccion"
FLASK_ENV="development"
FLASK_APP="app.py"
EOF

echo "✅ Base de datos configurada correctamente"
echo "Variables de entorno creadas en archivo .env"
echo "Para verificar la instalación, ejecute: ./verify_installation.sh"