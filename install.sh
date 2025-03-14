#!/bin/bash

echo "================================================"
echo "    SECTRACKER-PRO - Script de Instalación"
echo "================================================"

# Verificar si se está ejecutando como root
if [ "$EUID" -ne 0 ]; then 
    echo "Este script debe ejecutarse como root"
    exit 1
fi

# Crear directorio de la aplicación
APP_DIR="/opt/sectracker-pro"
echo "Creando directorio de la aplicación..."
mkdir -p $APP_DIR
cd $APP_DIR

# Copiar archivos de configuración
echo "Configurando variables de entorno..."
cat > .env << EOL
# Database configuration
DATABASE_URL=postgresql://sectracker:SecTracker2024!@db:5432/sectracker
DB_PASSWORD=SecTracker2024!

# Session configuration
SESSION_SECRET=6de939b8c6808ef3e999d77a6687897951e097934c87934533a50c56715acc74

# Admin configuration
ADMIN_INITIAL_PASSWORD=SecTracker2024!

# Resource limits
WEB_CPU_LIMIT=2       # Número de CPUs para la aplicación web
WEB_MEMORY_LIMIT=4G   # Memoria para la aplicación web
DB_CPU_LIMIT=1        # Número de CPUs para la base de datos
DB_MEMORY_LIMIT=2G    # Memoria para la base de datos

# Flask configuration
FLASK_APP=app.py
FLASK_ENV=production
FLASK_DEBUG=0
EOL

# Establecer permisos
echo "Configurando permisos..."
useradd -r -s /bin/false sectracker || true
chown -R sectracker:sectracker $APP_DIR
chmod -R 755 $APP_DIR

# Iniciar Docker Compose
echo "Iniciando contenedores Docker..."
docker-compose up -d

# Inicializar usuario admin
echo "Inicializando usuario administrador..."
sleep 10  # Esperar a que los contenedores estén listos
docker-compose exec -T web python init_admin.py

echo "================================================"
echo "    Instalación Completada"
echo "================================================"
echo "Para verificar el estado de los servicios ejecute:"
echo "docker-compose ps"
echo
echo "La aplicación estará disponible en:"
echo "http://localhost:5000"
echo "================================================"