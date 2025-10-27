from app import app, db
from models.user import User
from models.horario import Horario

def show_tables():
    print("\n=== USUARIOS ===")
    print("ID | Email | Rol | Fecha de Creación")
    print("-" * 60)
    users = User.query.all()
    for user in users:
        print(f"{user.id} | {user.email} | {user.role} | {user.created_at}")

    print("\n=== HORARIOS ===")
    print("ID | Día | Hora Inicio | Hora Fin | Materia | Docente | Salón")
    print("-" * 80)
    horarios = Horario.query.all()
    for horario in horarios:
        print(f"{horario.id} | {horario.dia} | {horario.hora_inicio} | {horario.hora_fin} | {horario.materia} | {horario.docente} | {horario.salon}")

if __name__ == '__main__':
    with app.app_context():
        show_tables()