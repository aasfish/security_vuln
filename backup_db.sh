#!/bin/bash

echo "=== SECTRACKER-PRO: Backup de Base de Datos ==="

# Verificar si pg_dump está disponible
if ! command -v pg_dump &> /dev/null; then
    echo "❌ Error: pg_dump no está instalado"
    exit 1
fi

# Crear directorio de backups si no existe
BACKUP_DIR="backups"
mkdir -p $BACKUP_DIR

# Generar nombre de archivo con timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.sql"

# Realizar el backup
echo "Creando backup de la base de datos..."
pg_dump -h $PGHOST -U $PGUSER -d $PGDATABASE > "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Backup creado exitosamente en: $BACKUP_FILE"
else
    echo "❌ Error al crear el backup"
    exit 1
fi
