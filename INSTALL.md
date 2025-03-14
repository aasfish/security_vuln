# Guía de Instalación de SECTRACKER-PRO

## Requisitos del Sistema

1. Sistema Operativo:
   - Ubuntu 20.04 o superior
   - Debian 11 o superior

2. Software Requerido:
   - Python 3.8 o superior
   - PostgreSQL 12 o superior
   - Git

## Pasos de Instalación

### 1. Preparación del Sistema

```bash
# Actualizar el sistema
sudo apt update
sudo apt upgrade -y

# Instalar Python y herramientas necesarias
sudo apt install -y python3 python3-pip python3-venv

# Instalar PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Iniciar PostgreSQL
sudo service postgresql start
```

### 2. Clonar el Repositorio

```bash
# Clonar el repositorio
git clone https://github.com/aasfish/security_vuln.git
cd security_vuln

# Dar permisos de ejecución a los scripts
chmod +x *.sh
```

### 3. Instalación Paso a Paso

#### 3.1. Instalar Dependencias

```bash
# Ejecutar script de instalación de dependencias
./install_dependencies.sh
```

Esto instalará:
- Flask y extensiones
- SQLAlchemy
- Gunicorn
- Otras dependencias necesarias

#### 3.2. Configurar Base de Datos

```bash
# Ejecutar script de configuración de base de datos
sudo ./setup_database.sh
```

Este script:
- Verifica PostgreSQL
- Crea el usuario de base de datos
- Crea la base de datos
- Configura los permisos
- Genera el archivo .env

#### 3.3. Verificar la Instalación

```bash
# Ejecutar script de verificación
./verify_installation.sh
```

Verifica:
- Dependencias de Python
- Conexión a la base de datos
- Creación de tablas
- Puerto disponible

#### 3.4. Crear Usuario Administrador

```bash
# Ejecutar script de creación de admin
./init_admin.sh
```

### 4. Iniciar la Aplicación

```bash
# Dar permisos de ejecución al script de inicio
chmod +x start.sh

# Iniciar la aplicación (esto cargará las variables de entorno automáticamente)
./start.sh
```

### 5. Acceder a la Aplicación

1. Abrir navegador web
2. Acceder a: http://localhost:5000
3. Credenciales iniciales:
   - Usuario: admin
   - Contraseña: SecTracker2024!

## Solución de Problemas

### Error: PostgreSQL no disponible

```bash
# Verificar estado de PostgreSQL
sudo service postgresql status

# Si está detenido, iniciarlo
sudo service postgresql start

# Verificar logs
sudo tail -f /var/log/postgresql/postgresql-12-main.log
```

### Error: No se puede conectar a la base de datos

1. Verificar archivo .env:
```bash
cat .env
```
Debe contener:
```
DATABASE_URL="postgresql://sectracker_user:SecTracker2024!@localhost:5432/sectracker"
```

2. Probar conexión manual:
```bash
psql -h localhost -U sectracker_user sectracker
```

### Error: Puerto 5000 en uso

```bash
# Encontrar proceso usando el puerto
sudo lsof -i :5000

# Detener el proceso
sudo kill <PID>

# O usar otro puerto
gunicorn --bind 0.0.0.0:5001 app:app
```

## Verificación Final

- [ ] PostgreSQL está instalado y ejecutándose
- [ ] Las dependencias de Python están instaladas
- [ ] La base de datos está creada y accesible
- [ ] El archivo .env está configurado correctamente
- [ ] Las tablas están creadas en la base de datos
- [ ] El usuario admin está creado
- [ ] La aplicación inicia sin errores
- [ ] Se puede acceder vía navegador web
- [ ] El login funciona correctamente

## Notas Adicionales

1. Es importante ejecutar los scripts en el orden especificado.
2. Algunos comandos requieren privilegios de superusuario (sudo).
3. Cambiar la contraseña del administrador después del primer inicio de sesión.
4. Para entornos de producción, configurar un proxy inverso (nginx) y SSL.

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