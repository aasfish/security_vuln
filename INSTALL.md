# Guía de Instalación Local de SECTRACKER-PRO

## Requisitos Previos

- Ubuntu/Debian (o distribución basada en estos)
- Python 3.8 o superior
- PostgreSQL 12 o superior
- Git

## 1. Preparación del Sistema

### 1.1. Verificar/Instalar PostgreSQL
```bash
# Verificar si PostgreSQL está instalado
sudo service postgresql status

# Si no está instalado, instalar:
sudo apt update
sudo apt install postgresql postgresql-contrib

# Iniciar PostgreSQL
sudo service postgresql start

# Verificar que está corriendo
sudo service postgresql status
```

### 1.2. Verificar Python
```bash
python3 --version
# Debe mostrar 3.8 o superior
```

## 2. Configuración del Proyecto

### 2.1. Clonar el Repositorio
```bash
git clone https://github.com/aasfish/security_vuln.git
cd security_vuln
```

### 2.2. Preparar Scripts
```bash
# Dar permisos de ejecución a los scripts
chmod +x install_dependencies.sh setup_database.sh verify_installation.sh init_admin.sh
```

## 3. Instalación

### 3.1. Instalar Dependencias de Python
```bash
./install_dependencies.sh
```

Verifica que la instalación sea exitosa. Deberías ver:
```
✅ Dependencias instaladas correctamente
```

### 3.2. Configurar Base de Datos
```bash
sudo ./setup_database.sh
```

Este script:
- Crea el usuario `sectracker_user`
- Crea la base de datos `sectracker`
- Configura los permisos necesarios
- Genera el archivo `.env`

Verifica que la salida muestre:
```
✅ Base de datos configurada correctamente
✅ Variables de entorno creadas en archivo .env
✅ Tablas creadas correctamente
```

### 3.3. Verificar la Instalación
```bash
./verify_installation.sh
```

Deberías ver:
```
✅ Dependencias de Python instaladas correctamente
✅ Conexión a la base de datos exitosa
✅ Tablas creadas correctamente
✅ Puerto 5000 disponible
```

### 3.4. Crear Usuario Administrador
```bash
./init_admin.sh
```

## 4. Iniciar la Aplicación

```bash
# Usando gunicorn (recomendado para producción)
gunicorn --bind 0.0.0.0:5000 app:app

# O usando Flask directamente (para desarrollo)
export FLASK_APP=app.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```

Accede a la aplicación en: http://localhost:5000

Credenciales iniciales:
- Usuario: admin
- Contraseña: SecTracker2024!

## 5. Solución de Problemas

### 5.1. Error de Conexión a PostgreSQL

Si ves errores como "could not connect to server" o "connection refused":

1. Verifica que PostgreSQL esté corriendo:
```bash
sudo service postgresql status
```

2. Verifica que puedes conectarte manualmente:
```bash
psql -h localhost -U sectracker_user sectracker
# Usa la contraseña: SecTracker2024!
```

3. Revisa el archivo `.env`:
```bash
cat .env
```
Asegúrate de que DATABASE_URL tenga el formato:
```
DATABASE_URL="postgresql://sectracker_user:SecTracker2024!@localhost:5432/sectracker"
```

### 5.2. Error "SESSION_SECRET not set"

Este es solo un mensaje de advertencia y no afecta el funcionamiento. El sistema generará una clave aleatoria automáticamente.

### 5.3. Error de Permisos en PostgreSQL

Si ves errores de permisos:

1. Conéctate como usuario postgres:
```bash
sudo -u postgres psql
```

2. Verifica/corrige los permisos:
```sql
ALTER USER sectracker_user WITH PASSWORD 'SecTracker2024!';
GRANT ALL PRIVILEGES ON DATABASE sectracker TO sectracker_user;
\c sectracker
GRANT ALL ON ALL TABLES IN SCHEMA public TO sectracker_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO sectracker_user;
```

### 5.4. Puerto 5000 en Uso

Si el puerto 5000 está ocupado:

1. Encuentra qué proceso usa el puerto:
```bash
sudo lsof -i :5000
```

2. Detén el proceso o usa otro puerto:
```bash
# Detener el proceso
sudo kill <PID>

# O usar otro puerto (por ejemplo, 5001)
gunicorn --bind 0.0.0.0:5001 app:app
```

## 6. Verificación Final

La instalación es exitosa si:

1. Puedes acceder a http://localhost:5000
2. Puedes iniciar sesión con el usuario admin
3. Ves el dashboard principal
4. Puedes acceder a todas las funcionalidades sin errores

Si encuentras algún problema no cubierto en esta guía, por favor:
1. Revisa los logs de la aplicación
2. Verifica los permisos de los archivos
3. Asegúrate de que todos los servicios necesarios estén corriendo
