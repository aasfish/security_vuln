#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 2 - Configuración de Base de Datos ==="

# Verificar si PostgreSQL está disponible
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: PostgreSQL no está disponible"
    exit 1
fi

# Usar las variables de entorno de Replit
DB_NAME=${PGDATABASE}
DB_USER=${PGUSER}
DB_PASSWORD=${PGPASSWORD}
DB_HOST=${PGHOST}
DB_PORT=${PGPORT}

# Verificar que todas las variables necesarias estén definidas
if [ -z "$DB_NAME" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASSWORD" ] || [ -z "$DB_HOST" ] || [ -z "$DB_PORT" ]; then
    echo "❌ Error: Variables de entorno de base de datos no configuradas"
    exit 1
fi

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

# Crear archivo .env con las variables de entorno
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
echo "Para verificar la instalación, ejecute: ./verify_installation.sh"