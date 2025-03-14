# SECTRACKER-PRO - Configuración Inicial

## Requisitos
- Python 3.x
- PostgreSQL
- Las dependencias listadas en `requirements.txt`

## Instalación en Ambiente Productivo

1. Clone el repositorio:
```bash
git clone <repositorio>/sectracker-pro.git
cd sectracker-pro
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

4. Haga ejecutable el script de inicialización:
```bash
chmod +x init_admin.sh
```

5. Ejecute el script de inicialización:
```bash
./init_admin.sh
```

## Credenciales Iniciales
- Usuario: admin
- Contraseña: SecTracker2024!

**IMPORTANTE:** Por seguridad, cambie la contraseña del administrador después del primer inicio de sesión.

## Ejecución de la Aplicación
```bash
python app.py
```

La aplicación estará disponible en: http://localhost:5000
