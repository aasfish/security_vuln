# SECTRACKER-PRO - Sistema de Gestión de Vulnerabilidades

## Requisitos del Sistema
- Python 3.11 o superior
- PostgreSQL Database
- Conexión a Internet

## Instalación Local

### 1. Configuración del Entorno
```bash
# Instalar dependencias de Python
pip install flask flask-sqlalchemy flask-login psycopg2-binary gunicorn email-validator flask-wtf

# Configurar PostgreSQL
sudo -u postgres psql
CREATE DATABASE sectracker;
CREATE USER sectracker WITH PASSWORD 'SecTracker2024!';
GRANT ALL PRIVILEGES ON DATABASE sectracker TO sectracker;
```

### 2. Variables de Entorno
Configura las siguientes variables:
```bash
export DATABASE_URL="postgresql://sectracker:SecTracker2024!@localhost:5432/sectracker"
export SESSION_SECRET="tu_clave_secreta_aqui"
```

### 3. Iniciar la Aplicación
```bash
# Inicializar la base de datos y crear usuario admin
python init_admin.py

# Iniciar el servidor
gunicorn --bind 0.0.0.0:5000 app:app
```

## Solución de Problemas

### Error de conexión a la base de datos
1. Verifica que PostgreSQL esté corriendo: `sudo systemctl status postgresql`
2. Confirma las credenciales en DATABASE_URL
3. Verifica los permisos de la base de datos

## Soporte

Para reportar problemas o sugerir mejoras, por favor crear un issue en el repositorio:
https://github.com/aasfish/AS/issues