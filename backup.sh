#!/bin/bash

echo "=== SECTRACKER-PRO: Backup del Sistema ==="

# Verificar si los scripts necesarios existen
if [ ! -f "./backup_db.sh" ]; then
    echo "❌ Error: backup_db.sh no encontrado"
    exit 1
fi

# Ejecutar backup de la base de datos
echo "Iniciando backup de la base de datos..."
./backup_db.sh

if [ $? -eq 0 ]; then
    echo "✅ Backup completado exitosamente"
else
    echo "❌ Error durante el backup"
    exit 1
fi
