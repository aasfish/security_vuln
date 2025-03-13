from datetime import datetime
from database import db

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

class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    nombre_host = db.Column(db.String(200))
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos.id'), nullable=False)
    vulnerabilidades = db.relationship('Vulnerabilidad', backref='host', lazy=True, cascade='all, delete-orphan')

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