import os
from app import app, db
from models import User
from datetime import datetime

def create_admin_user():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Usar una contraseña del ambiente o generar una aleatoria
            admin_password = os.environ.get('ADMIN_INITIAL_PASSWORD') or os.urandom(24).hex()

            admin = User(
                username='admin',
                email='admin@sectracker.pro',
                role='admin',
                created_at=datetime.utcnow()
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            print("Username: admin")
            print(f"Password: {admin_password}")
            print("\nIMPORTANTE: Por favor, cambie esta contraseña después del primer inicio de sesión")
        else:
            print("Admin user already exists")

if __name__ == "__main__":
    create_admin_user()