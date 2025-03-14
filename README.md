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

## Requisitos del Sistema
- Docker y Docker Compose
- 4GB RAM mínimo recomendado
- 2 CPU cores mínimo recomendado

## Guía de Instalación

### 1. Preparación del Servidor
```bash
# Actualizar el sistema
sudo apt-get update && sudo apt-get upgrade -y

# Instalar Docker y Docker Compose
sudo apt-get install -y docker.io docker-compose

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
```

### 2. Instalación de la Aplicación

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

3. Configurar recursos según tu servidor en .env:
```ini
# Ejemplo para servidor con 16GB RAM
WEB_CPU_LIMIT=4       # 4 CPUs para la aplicación web
WEB_MEMORY_LIMIT=8G   # 8GB de RAM para la web
DB_CPU_LIMIT=2        # 2 CPUs para la base de datos
DB_MEMORY_LIMIT=4G    # 4GB para la base de datos

# Configuración de seguridad
SESSION_SECRET=tu_clave_secreta_aqui
DB_PASSWORD=tu_contraseña_segura_aqui
```

4. Iniciar la aplicación:
```bash
docker-compose up -d
```

5. Crear usuario administrador:
```bash
docker-compose exec web ./init_admin.sh
```

La aplicación estará disponible en: http://localhost:5000

## Credenciales Iniciales
- Usuario: admin
- Contraseña: La mostrada al ejecutar init_admin.sh

**¡IMPORTANTE!** Por seguridad, cambie la contraseña del administrador después del primer inicio de sesión.

## Mantenimiento

### Respaldos de Base de Datos
```bash
# Crear respaldo
docker-compose exec db pg_dump -U sectracker sectracker > backup.sql

# Restaurar respaldo
docker-compose exec -T db psql -U sectracker sectracker < backup.sql
```

### Actualización del Sistema
```bash
# Actualizar a la última versión
git pull

# Reconstruir e iniciar contenedores
docker-compose down
docker-compose up -d --build
```

### Logs del Sistema
```bash
# Ver logs de la aplicación web
docker-compose logs web

# Ver logs de la base de datos
docker-compose logs db
```

## Resolución de Problemas

### Error de Permisos
Si encuentras errores de permisos:
```bash
# Ajustar permisos de archivos
sudo chown -R $(whoami):$(whoami) .
```

### Error de Conexión a la Base de Datos
Verificar que la base de datos está corriendo:
```bash
docker-compose ps
docker-compose logs db
```

### Reinicio de Servicios
```bash
# Reiniciar todos los servicios
docker-compose restart

# Reiniciar servicio específico
docker-compose restart web
docker-compose restart db
```

## Seguridad
- ✅ Todas las contraseñas se almacenan hasheadas
- ✅ Sistema de logging para auditoría
- ✅ Control de acceso basado en roles
- ✅ Variables de entorno para configuraciones sensibles

## Soporte
Para reportar problemas o sugerir mejoras, por favor crear un issue en el repositorio:
https://github.com/aasfish/escaneo_vuln/issues

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