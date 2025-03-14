# SECTRACKER-PRO - Sistema de Gestión de Vulnerabilidades

## Descripción
SECTRACKER-PRO es una aplicación web para la gestión integral de vulnerabilidades de seguridad, enfocada en el monitoreo y reporte de seguridad de forma amigable.

## Características
- Dashboard interactivo de vulnerabilidades
- Gestión de múltiples sedes
- Seguimiento de vulnerabilidades
- Generación de informes técnicos y ejecutivos
- Autenticación y control de acceso
- HTTPS forzado para mayor seguridad

## Requisitos
- Docker y Docker Compose
- O alternativamente:
  - Python 3.x
  - PostgreSQL
  - Las dependencias listadas en `requirements.txt`

## Instalación con Docker (Recomendado)

1. Clone el repositorio:
```bash
git clone https://github.com/aasfish/Vulntracker.git
cd Vulntracker
```

2. Cree un archivo .env con la configuración necesaria:
```bash
echo "SESSION_SECRET=your_secret_key_here" > .env
```

3. Inicie los contenedores:
```bash
docker-compose up -d
```

4. Cree el usuario administrador inicial:
```bash
docker-compose exec web ./init_admin.sh
```

La aplicación estará disponible en: https://localhost:5000

## Instalación Manual
1. Clone el repositorio:
```bash
git clone https://github.com/aasfish/Vulntracker.git
cd Vulntracker
```

2. Instale las dependencias:
```bash
pip install -r requirements.txt
```

3. Configure las variables de entorno:
```bash
export DATABASE_URL="postgresql://usuario:contraseña@localhost:5432/sectracker"
export SESSION_SECRET="tu_secreto_seguro"
```

4. Ejecute el script de inicialización:
```bash
chmod +x init_admin.sh
./init_admin.sh
```

## Credenciales Iniciales
- Usuario: admin
- Contraseña: SecTracker2024!

**IMPORTANTE:** Por seguridad, cambie la contraseña del administrador después del primer inicio de sesión.

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

## Seguridad
- Todas las conexiones son forzadas a HTTPS
- Las contraseñas se almacenan hasheadas
- Sistema de logging para auditoría
- Control de acceso basado en roles

## Base de Datos
La aplicación utiliza PostgreSQL como base de datos. Al usar Docker Compose:
- La base de datos se crea automáticamente
- Los datos se persisten en un volumen Docker
- No es necesario instalar PostgreSQL en el host
- Las credenciales se configuran mediante variables de entorno

## Respaldo y Restauración
Para respaldar la base de datos:
```bash
docker-compose exec db pg_dump -U sectracker sectracker > backup.sql
```

Para restaurar:
```bash
docker-compose exec -T db psql -U sectracker sectracker < backup.sql
```

## Contribuir
1. Fork el repositorio
2. Cree una rama para su característica (`git checkout -b feature/AmazingFeature`)
3. Commit sus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abra un Pull Request

## Licencia
Este proyecto está licenciado bajo la Licencia MIT - vea el archivo LICENSE para más detalles.