from datetime import datetime
from database import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        """Generate password hash using werkzeug.security"""
        if password:
            self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against stored hash"""
        if self.password_hash and password:
            return check_password_hash(self.password_hash, password)
        return False

    def get_id(self):
        """Required for Flask-Login"""
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username}>'

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

    user = db.relationship('User', backref='activities')

class Sede(db.Model):
    __tablename__ = 'sedes'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    activa = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<Sede {self.nombre}>'

class Escaneo(db.Model):
    __tablename__ = 'escaneos'

    id = db.Column(db.Integer, primary_key=True)
    sede_id = db.Column(db.Integer, db.ForeignKey('sedes.id'), nullable=False)
    fecha_escaneo = db.Column(db.Date, nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    hosts = db.relationship('Host', backref='escaneo', lazy=True, cascade='all, delete-orphan')
    sede = db.relationship('Sede', backref='escaneos', lazy=True)

    def __repr__(self):
        return f'<Escaneo {self.fecha_escaneo}>'

class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    nombre_host = db.Column(db.String(200))
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos.id'), nullable=False)
    vulnerabilidades = db.relationship('Vulnerabilidad', backref='host', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Host {self.ip}>'

class Vulnerabilidad(db.Model):
    __tablename__ = 'vulnerabilidades'

    id = db.Column(db.Integer, primary_key=True)
    oid = db.Column(db.String(100), nullable=False)
    nvt = db.Column(db.String(500), nullable=False)
    nivel_amenaza = db.Column(db.String(50), nullable=False)
    cvss = db.Column(db.String(10))
    puerto = db.Column(db.String(50))
    resumen = db.Column(db.Text)
    impacto = db.Column(db.Text)
    solucion = db.Column(db.Text)
    metodo_deteccion = db.Column(db.Text)
    referencias = db.Column(db.JSON)
    estado = db.Column(db.String(20), default='ACTIVA')
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)

    def __repr__(self):
        return f'<Vulnerabilidad {self.nvt}>'