# SECTRACKER-PRO - Sistema de Gestión de Vulnerabilidades

## Descripción
SECTRACKER-PRO es una aplicación web para la gestión integral de vulnerabilidades de seguridad, enfocada en el monitoreo y reporte de seguridad de forma amigable.

## Características Principales
- 🔍 Dashboard interactivo de vulnerabilidades
- 🏢 Gestión de múltiples sedes
- 📊 Seguimiento de vulnerabilidades
- 📑 Generación de informes técnicos y ejecutivos
- 🔐 Autenticación y control de acceso
- 🛡️ HTTPS forzado para mayor seguridad

## Requisitos
- Docker y Docker Compose
- 4GB RAM mínimo recomendado
- 2 CPU cores mínimo recomendado

## Instalación Rápida

1. Clonar el repositorio:
```bash
git clone https://github.com/aasfish/escaneo_vuln.git
cd escaneo_vuln
```

2. Configurar variables de entorno:
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

3. Iniciar con Docker Compose:
```bash
docker-compose up -d
```

4. Crear usuario administrador:
```bash
docker-compose exec web ./init_admin.sh
```

La aplicación estará disponible en: http://localhost:5000

## Configuración de Recursos

Puedes ajustar los recursos según tu servidor en el archivo `.env`:

```
# Ejemplo para servidor con 16GB RAM
WEB_CPU_LIMIT=4       # 4 CPUs para la aplicación web
WEB_MEMORY_LIMIT=8G   # 8GB de RAM para la web
DB_CPU_LIMIT=2        # 2 CPUs para la base de datos
DB_MEMORY_LIMIT=4G    # 4GB para la base de datos
```

## Seguridad
- ✅ Todas las contraseñas se almacenan hasheadas
- ✅ Sistema de logging para auditoría
- ✅ Control de acceso basado en roles
- ✅ Variables de entorno para configuraciones sensibles

## Mantenimiento

### Respaldos
```bash
# Crear respaldo
docker-compose exec db pg_dump -U sectracker sectracker > backup.sql

# Restaurar respaldo
docker-compose exec -T db psql -U sectracker sectracker < backup.sql
```

### Actualización
```bash
git pull
docker-compose down
docker-compose up -d --build
```

## Soporte
Para reportar problemas o sugerir mejoras, por favor crear un issue en el repositorio.

## Licencia
Este proyecto está licenciado bajo la Licencia MIT.

## Estructura del Proyecto
```
sectracker-pro/
├── app.py           # Aplicación principal
├── models.py        # Modelos de datos
├── templates/       # Plantillas HTML
├── static/         # Archivos estáticos
├── docker/         # Configuración de Docker
└── scripts/        # Scripts de utilidad
```

## Credenciales Iniciales
- Usuario: admin
- Contraseña: SecTracker2024!

**IMPORTANTE:** Por seguridad, cambie la contraseña del administrador después del primer inicio de sesión.

## Base de Datos
La aplicación utiliza PostgreSQL como base de datos. Al usar Docker Compose:
- La base de datos se crea automáticamente
- Los datos se persisten en un volumen Docker
- No es necesario instalar PostgreSQL en el host
- Las credenciales se configuran mediante variables de entorno

## Despliegue en Producción (Linux)

### 1. Preparación del Servidor
```bash
# Actualizar el sistema
sudo apt-get update && sudo apt-get upgrade -y

# Instalar Docker y Docker Compose
sudo apt-get install -y docker.io docker-compose

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
```

### 2. Configuración de Firewall
```bash
# Permitir HTTPS
sudo ufw allow 443/tcp

# Permitir HTTP (para redirección a HTTPS)
sudo ufw allow 80/tcp

# Activar firewall
sudo ufw enable
```

### 3. Despliegue de la Aplicación
```bash
# Clonar el repositorio
git clone https://github.com/aasfish/Vulntracker.git
cd Vulntracker

# Configurar variables de entorno
cat > .env << EOL
SESSION_SECRET=$(openssl rand -hex 32)
EOL

# Iniciar los contenedores
docker-compose up -d

# Crear usuario administrador
docker-compose exec web ./init_admin.sh
```

### 4. Configuración de Proxy Inverso (Nginx)
```bash
# Instalar Nginx
sudo apt-get install -y nginx

# Configurar Nginx como proxy inverso
sudo nano /etc/nginx/sites-available/sectracker
```

Contenido del archivo de configuración:
```nginx
server {
    listen 80;
    server_name tu-dominio.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name tu-dominio.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Activar el sitio
sudo ln -s /etc/nginx/sites-available/sectracker /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 5. Mantenimiento

#### Actualización de la Aplicación
```bash
cd Vulntracker
git pull
docker-compose down
docker-compose up -d --build
```

#### Respaldos Automáticos
Crear script de respaldo:
```bash
#!/bin/bash
BACKUP_DIR="/backups/sectracker"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
docker-compose exec -T db pg_dump -U sectracker sectracker > $BACKUP_DIR/backup_$TIMESTAMP.sql
```

Agregar a crontab:
```bash
0 2 * * * /path/to/backup-script.sh
```

## Contribuir
1. Fork el repositorio
2. Cree una rama para su característica (`git checkout -b feature/AmazingFeature`)
3. Commit sus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abra un Pull Request

## Licencia
Este proyecto está licenciado bajo la Licencia MIT - vea el archivo LICENSE para más detalles.