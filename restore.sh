#!/bin/bash

echo "=== SECTRACKER-PRO: Restauración del Sistema ==="

# Verificar si se proporcionó un archivo
if [ $# -ne 1 ]; then
    echo "❌ Error: Debe especificar el archivo de backup"
    echo "Uso: ./restore.sh archivo_backup.sql"
    exit 1
fi

# Verificar si los scripts necesarios existen
if [ ! -f "./restore_db.sh" ]; then
    echo "❌ Error: restore_db.sh no encontrado"
    exit 1
fi

# Ejecutar restauración de la base de datos
echo "Iniciando restauración del sistema..."
./restore_db.sh "$1"

if [ $? -eq 0 ]; then
    echo "✅ Restauración completada exitosamente"
else
    echo "❌ Error durante la restauración"
    exit 1
fi
