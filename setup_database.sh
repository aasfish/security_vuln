#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 2 - Configuración de Base de Datos ==="

# Definir variables locales
DB_NAME="sectracker"
DB_USER="sectracker_user"
DB_PASSWORD="SecTracker2024!"
DB_HOST="localhost"
DB_PORT="5432"

# Verificar si PostgreSQL está disponible
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: PostgreSQL no está disponible"
    echo "Instalando PostgreSQL..."
    sudo apt-get update
    sudo apt-get install -y postgresql postgresql-contrib
    sudo service postgresql start
    sleep 5
fi

# Verificar nuevamente si PostgreSQL está disponible
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: No se pudo iniciar PostgreSQL"
    exit 1
fi

echo "✅ PostgreSQL está disponible"

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

echo "✅ Base de datos configurada correctamente"

# Crear archivo .env con las variables de entorno
echo "Creando archivo .env..."
cat > .env << EOF
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
SESSION_SECRET="$(openssl rand -hex 32)"
FLASK_ENV="development"
FLASK_APP="app.py"
EOF

echo "✅ Variables de entorno creadas en archivo .env"

# Crear las tablas de la base de datos
echo "Creando tablas de la base de datos..."
python3 create_tables.py

if [ $? -ne 0 ]; then
    echo "❌ Error: Falló la creación de las tablas"
    exit 1
fi

echo "✅ Tablas creadas correctamente"
echo "Para continuar con la instalación, ejecute: ./verify_installation.sh"