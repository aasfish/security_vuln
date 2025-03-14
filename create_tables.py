from app import app, db
from models import *  # This imports all models

def create_tables():
    with app.app_context():
        # Drop all tables first to ensure clean slate
        db.drop_all()
        # Create all tables based on models
        db.create_all()
        print("✅ Tablas creadas exitosamente")

if __name__ == "__main__":
    create_tables()