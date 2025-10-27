from app import app, db
from models.user import User

def show_users():
    print("\n=== TABLA DE USUARIOS ===")
    print("ID | Email | Rol | Fecha de Creación")
    print("-" * 70)
    users = User.query.all()
    for user in users:
        print(f"{user.id} | {user.email} | {user.role} | {user.created_at}")

if __name__ == '__main__':
    with app.app_context():
        show_users()