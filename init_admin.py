import os
import logging
from app import app, db
from models import User
from datetime import datetime

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_admin():
    """Initialize admin user with proper password hashing"""
    try:
        with app.app_context():
            # Verificar si ya existe un usuario admin
            admin = User.query.filter_by(username='admin').first()
            if admin:
                logger.info("El usuario administrador ya existe")
                return

            # Crear nuevo usuario admin
            admin = User(
                username='admin',
                email='admin@sectracker.local',
                is_admin=True,
                role='admin',
                created_at=datetime.utcnow()
            )
            admin.set_password('SecTracker2024!')

            # Guardar en la base de datos
            db.session.add(admin)
            db.session.commit()

            logger.info("Usuario administrador creado exitosamente")
            logger.info("Usuario: admin")
            logger.info("Contraseña: SecTracker2024!")

    except Exception as e:
        logger.error(f"Error al crear el usuario administrador: {str(e)}")
        db.session.rollback()
        raise

if __name__ == '__main__':
    init_admin()