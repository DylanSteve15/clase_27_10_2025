from .user import db
from datetime import datetime

class Horario(db.Model):
    __tablename__ = 'horarios'

    id = db.Column(db.Integer, primary_key=True)
    materia = db.Column(db.String(100), nullable=False)
    docente = db.Column(db.String(120), nullable=False)
    dia = db.Column(db.String(20), nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fin = db.Column(db.Time, nullable=False)
    salon = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'materia': self.materia,
            'docente': self.docente,
            'dia': self.dia,
            'hora_inicio': self.hora_inicio.strftime('%H:%M'),
            'hora_fin': self.hora_fin.strftime('%H:%M'),
            'salon': self.salon
        }