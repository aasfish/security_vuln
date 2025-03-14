import os
import logging
from app import db
from models import User
from werkzeug.security import generate_password_hash

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_admin():
    try:
        # Obtener la contraseña del ambiente o usar el valor por defecto
        admin_password = os.environ.get('ADMIN_INITIAL_PASSWORD', 'SecTracker2024!')
        
        # Verificar si ya existe un usuario admin
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            logger.info("El usuario administrador ya existe")
            return
        
        # Crear nuevo usuario admin
        admin = User(
            username='admin',
            email='admin@sectracker.local',
            password_hash=generate_password_hash(admin_password),
            is_admin=True
        )
        
        # Guardar en la base de datos
        db.session.add(admin)
        db.session.commit()
        
        logger.info("Usuario administrador creado exitosamente")
        logger.info("Usuario: admin")
        logger.info(f"Contraseña: {admin_password}")
        
    except Exception as e:
        logger.error(f"Error al crear el usuario administrador: {str(e)}")
        raise

if __name__ == '__main__':
    init_admin()
