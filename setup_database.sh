#!/bin/bash

echo "=== Instalando SECTRACKER-PRO: Paso 2 - Configuración de Base de Datos ==="

# Verificar si PostgreSQL está disponible
if ! pg_isready > /dev/null 2>&1; then
    echo "❌ Error: PostgreSQL no está disponible"
    exit 1
fi

# Exportar las variables de entorno de Replit si existen
if [ -n "$REPL_ID" ] && [ -n "$REPL_OWNER" ]; then
    export PGDATABASE=${PGDATABASE}
    export PGUSER=${PGUSER}
    export PGPASSWORD=${PGPASSWORD}
    export PGHOST=${PGHOST}
    export PGPORT=${PGPORT}
fi

# Verificar que todas las variables necesarias estén definidas
if [ -z "$PGDATABASE" ] || [ -z "$PGUSER" ] || [ -z "$PGPASSWORD" ] || [ -z "$PGHOST" ] || [ -z "$PGPORT" ]; then
    echo "❌ Error: Variables de entorno de base de datos no configuradas"
    exit 1
fi

# Crear archivo .env con las variables de entorno
echo "Creando archivo .env..."
cat > .env << EOF
DATABASE_URL="postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}"
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