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
if ! pg_isready > /dev/null 2>&1; then
    echo "Iniciando PostgreSQL..."
    sudo service postgresql start
    sleep 5  # Dar tiempo a que PostgreSQL inicie completamente
fi

# Verificar si PostgreSQL está corriendo
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: No se pudo iniciar PostgreSQL"
    exit 1
fi

# Usar las variables de entorno de Replit si están disponibles
DB_NAME=${PGDATABASE:-"sectracker"}
DB_USER=${PGUSER:-"sectracker_user"}
DB_PASSWORD=${PGPASSWORD:-"SecTracker2024!"}
DB_HOST=${PGHOST:-"localhost"}
DB_PORT=${PGPORT:-"5432"}

# Crear usuario y base de datos
echo "Configurando base de datos..."
sudo -u postgres psql <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '$DB_USER') THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    END IF;
END
\$\$;

DROP DATABASE IF EXISTS $DB_NAME;
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
SESSION_SECRET="$(openssl rand -hex 32)"
FLASK_ENV="development"
FLASK_APP="app.py"
EOF

echo "✅ Base de datos configurada correctamente"
echo "Variables de entorno creadas en archivo .env"

# Crear las tablas usando Python directamente sin activar el entorno virtual
echo "Creando tablas de la base de datos..."
python3 create_tables.py

if [ $? -ne 0 ]; then
    echo "❌ Error: Falló la creación de las tablas"
    exit 1
fi

echo "✅ Tablas creadas correctamente"
echo "Para verificar la instalación, ejecute: ./verify_installation.sh"