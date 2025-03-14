#!/bin/bash

echo "========================================"
echo "    SECTRACKER-PRO - Inicialización"
echo "========================================"
echo
echo "Creando usuario administrador inicial..."
echo

# Ejecutar el script de Python para crear el admin
python init_admin.py

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