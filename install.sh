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

# Instalar dependencias del sistema
echo "Instalando dependencias del sistema..."
apt-get update
apt-get install -y python3 python3-pip postgresql postgresql-contrib

# Crear usuario de servicio
echo "Creando usuario de servicio..."
useradd -r -s /bin/false sectracker

# Instalar dependencias de Python
echo "Instalando dependencias de Python..."
pip3 install -r requirements.txt

# Configurar la base de datos
echo "Configurando la base de datos..."
sudo -u postgres psql -c "CREATE DATABASE sectracker;"
sudo -u postgres psql -c "CREATE USER sectracker WITH PASSWORD 'SecTracker2024!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sectracker TO sectracker;"

# Configurar variables de entorno
echo "Configurando variables de entorno..."
cat > /etc/sectracker-pro.env << EOL
DATABASE_URL="postgresql://sectracker:SecTracker2024!@localhost/sectracker"
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

# Inicializar usuario admin
echo "Inicializando usuario administrador..."
./init_admin.sh

echo "================================================"
echo "    Instalación Completada"
echo "================================================"
echo "Para iniciar el servicio ejecute:"
echo "systemctl start sectracker"
echo
echo "La aplicación estará disponible en:"
echo "http://localhost:5000"
echo "================================================"
