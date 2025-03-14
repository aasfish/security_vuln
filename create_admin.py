from app import app, db
from models import User
from datetime import datetime

def create_admin_user():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@sectracker.pro',
                role='admin',
                created_at=datetime.utcnow()
            )
            admin.set_password('SecTracker2024!')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            print("Username: admin")
            print("Password: SecTracker2024!")
        else:
            print("Admin user already exists")

if __name__ == "__main__":
    create_admin_user()
