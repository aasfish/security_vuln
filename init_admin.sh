#!/bin/bash

echo "========================================"
echo "    SECTRACKER-PRO - Inicialización"
echo "========================================"
echo
echo "Creando usuario administrador inicial..."
echo

# Cargar variables de entorno
if [ -f .env ]; then
    set -a
    source .env
    set +a
else
    echo "❌ Error: Archivo .env no encontrado"
    exit 1
fi

# Verificar que DATABASE_URL está configurada
if [ -z "$DATABASE_URL" ]; then
    echo "❌ Error: DATABASE_URL no está configurada"
    exit 1
fi

# Ejecutar el script de Python para crear el admin
python3 init_admin.py

if [ $? -eq 0 ]; then
    echo
    echo "========================================"
    echo "Para acceder a SECTRACKER-PRO use:"
    echo "----------------------------------------"
    echo "URL: http://localhost:5000"
    echo "Usuario: admin"
    echo "Contraseña: SecTracker2024!"
    echo "========================================"
    echo
    echo "¡IMPORTANTE! Por seguridad, cambie la"
    echo "contraseña después del primer inicio"
    echo "de sesión."
    echo "========================================"
else
    echo "❌ Error: No se pudo crear el usuario administrador"
    exit 1
fi