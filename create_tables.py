from app import app, db
from models import *  # This imports all models

def create_tables():
    with app.app_context():
        # Create all tables based on models
        db.create_all()
        print("✅ Tablas creadas exitosamente")

if __name__ == "__main__":
    create_tables()
