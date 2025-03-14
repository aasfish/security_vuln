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
cat > /etc/sectracker-pro.env << EOL
DATABASE_URL="postgresql://sectracker:SecTracker2024!@db:5432/sectracker"
SESSION_SECRET="$(openssl rand -hex 32)"
EOL

# Configurar servicio systemd
echo "Configurando servicio systemd..."
cp sectracker.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sectracker

# Establecer permisos
echo "Configurando permisos..."
chown -R sectracker:sectracker $APP_DIR
chmod -R 755 $APP_DIR

# Iniciar Docker Compose
echo "Iniciando contenedores Docker..."
docker-compose up -d

# Inicializar usuario admin
echo "Inicializando usuario administrador..."
sleep 10  # Esperar a que los contenedores estén listos
docker-compose exec -T web ./init_admin.sh

echo "================================================"
echo "    Instalación Completada"
echo "================================================"
echo "Para verificar el estado del servicio ejecute:"
echo "systemctl status sectracker"
echo
echo "La aplicación estará disponible en:"
echo "http://localhost:5000"
echo "================================================"