#!/bin/bash

echo "=== SECTRACKER-PRO: Restauración de Base de Datos ==="

# Verificar si psql está disponible
if ! command -v psql &> /dev/null; then
    echo "❌ Error: psql no está instalado"
    exit 1
fi

# Verificar variables de entorno
if [ -z "$PGHOST" ] || [ -z "$PGUSER" ] || [ -z "$PGDATABASE" ]; then
    echo "❌ Error: Variables de entorno no configuradas"
    echo "Por favor, asegúrate de que las siguientes variables estén configuradas:"
    echo "PGHOST, PGUSER, PGDATABASE"
    exit 1
fi

# Verificar si se proporcionó un archivo
if [ $# -ne 1 ]; then
    echo "❌ Error: Debe especificar el archivo de backup"
    echo "Uso: ./restore_db.sh archivo_backup.sql"
    exit 1
fi

BACKUP_FILE=$1

# Verificar si el archivo existe
if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Error: El archivo $BACKUP_FILE no existe"
    exit 1
fi

# Restaurar la base de datos
echo "Restaurando base de datos desde: $BACKUP_FILE"
if [ -n "$PGPASSWORD" ]; then
    PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" < "$BACKUP_FILE"
else
    psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" < "$BACKUP_FILE"
fi

if [ $? -eq 0 ]; then
    echo "✅ Base de datos restaurada exitosamente"
else
    echo "❌ Error al restaurar la base de datos"
    exit 1
fi