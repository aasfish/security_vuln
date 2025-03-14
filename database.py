import os
import logging
import time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configurar logging
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

def init_db(app):
    """Initialize database with the Flask app"""
    max_retries = 5
    retry_delay = 5  # segundos

    for attempt in range(max_retries):
        try:
            database_url = os.environ.get("DATABASE_URL")
            if not database_url:
                raise ValueError("DATABASE_URL environment variable is not set")

            app.config["SQLALCHEMY_DATABASE_URI"] = database_url
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
                "pool_recycle": 300,
                "pool_pre_ping": True
            }
            app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

            db.init_app(app)

            with app.app_context():
                # Importar modelos aquí para evitar referencias circulares
                from models import User, ActivityLog, Sede, Escaneo, Host, Vulnerabilidad

                # Crear todas las tablas según los modelos
                db.create_all()

                logger.info("Database initialized successfully")
                return

        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Error initializing database after {max_retries} attempts: {str(e)}")
                raise