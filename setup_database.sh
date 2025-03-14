#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 2 - Configuración de Base de Datos ==="

# Definir variables locales
DB_NAME="sectracker"
DB_USER="sectracker_user"
DB_PASSWORD="SecTracker2024!"
DB_HOST="localhost"
DB_PORT="5432"

# Verificar si se está ejecutando como root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Este script debe ejecutarse como root (usando sudo)"
    exit 1
fi

# Verificar si PostgreSQL está disponible
if ! command -v psql &> /dev/null; then
    echo "❌ Error: PostgreSQL no está instalado"
    echo "Instalando PostgreSQL..."
    apt-get update
    apt-get install -y postgresql postgresql-contrib
    service postgresql start
    sleep 5
fi

# Verificar si PostgreSQL está en ejecución
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: PostgreSQL no está en ejecución"
    echo "Iniciando PostgreSQL..."
    service postgresql start
    sleep 5

    if ! pg_isready > /dev/null 2>&1; then
        echo "❌ Error: No se pudo iniciar PostgreSQL"
        exit 1
    fi
fi

echo "✅ PostgreSQL está disponible"

# Crear usuario y base de datos
echo "Configurando base de datos..."
su - postgres -c "psql <<EOF
DO \\\$\\\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '$DB_USER') THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    END IF;
END
\\\$\\\$;

DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME WITH OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
\\c $DB_NAME
GRANT ALL ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
EOF"

if [ $? -ne 0 ]; then
    echo "❌ Error: Falló la creación de la base de datos"
    exit 1
fi

echo "✅ Base de datos configurada correctamente"

# Exportar variables de entorno para el script actual
export DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
export SESSION_SECRET="$(openssl rand -hex 32)"
export FLASK_ENV="development"
export FLASK_APP="app.py"

# Crear archivo .env con las variables de entorno
echo "Creando archivo .env..."
ENV_FILE=".env"
cat > $ENV_FILE << EOF
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
SESSION_SECRET="$(openssl rand -hex 32)"
FLASK_ENV="development"
FLASK_APP="app.py"
EOF

# Verificar que el archivo .env se creó correctamente
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Error: No se pudo crear el archivo .env"
    exit 1
fi

# Dar permisos al archivo .env y al directorio
CURRENT_USER=$(who am i | awk '{print $1}')
SCRIPT_DIR=$(pwd)
chown -R $CURRENT_USER:$CURRENT_USER $SCRIPT_DIR
chmod 600 $ENV_FILE

echo "✅ Variables de entorno creadas en archivo .env"

# Verificar que podemos conectarnos a la base de datos
echo "Verificando conexión a la base de datos..."
if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c '\q' 2>/dev/null; then
    echo "✅ Conexión a la base de datos verificada"
else
    echo "❌ Error: No se puede conectar a la base de datos"
    exit 1
fi

# Verificar que las variables de entorno están configuradas
if [ -z "$DATABASE_URL" ]; then
    echo "❌ Error: DATABASE_URL no está configurada"
    exit 1
fi

# Crear las tablas de la base de datos
echo "Creando tablas de la base de datos..."
cd $SCRIPT_DIR
sudo -E -u $CURRENT_USER python3 create_tables.py

if [ $? -eq 0 ]; then
    echo "✅ Tablas creadas correctamente"
else
    echo "❌ Error: Falló la creación de las tablas"
    exit 1
fi

echo "Para continuar con la instalación, ejecute: ./verify_installation.sh"