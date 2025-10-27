from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import os
import requests
import logging
from logging.handlers import RotatingFileHandler
import colorlog
from datetime import datetime, timedelta
from functools import wraps
from models.user import db, User
from flask_migrate import Migrate

# Cargar variables de entorno
load_dotenv()

# Importar modelos
from models.horario import Horario
from datetime import datetime, time

# Configuración de la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(basedir, "app.db")}')

# Configuración de la aplicación
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key-for-development')
app.config['API_URL'] = os.getenv('API_URL', 'http://localhost:5000')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar la base de datos
db.init_app(app)
migrate = Migrate(app, db)

# Configuración del sistema de logging
def setup_logger():
    logger = logging.getLogger('frontend_app')
    logger.setLevel(logging.DEBUG)

    # Crear el directorio logs si no existe
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Handler para archivo
    file_handler = RotatingFileHandler(
        'logs/frontend.log', 
        maxBytes=1024 * 1024,  # 1MB
        backupCount=10
    )
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Handler para consola con colores
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    color_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(levelname)s - %(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(color_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logger()

# Decorator para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            logger.warning("Intento de acceso sin autenticación")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si ya hay una sesión activa, redirigir al dashboard
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Por favor ingresa email y contraseña', 'error')
            return render_template('login.html')

        try:
            # Buscar usuario por email
            user = User.query.filter_by(email=email).first()
            
            # Verificar credenciales
            if user and user.check_password(password):
                # Crear sesión del usuario
                session.clear()  # Limpiar cualquier sesión anterior
                session['user'] = {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role.lower()  # Asegurar que el rol esté en minúsculas
                }
                session.permanent = True
                
                # Registrar el inicio de sesión
                logger.info(f"Usuario {email} ha iniciado sesión como {user.role}")
                
                # Mensaje de bienvenida
                flash(f'Bienvenido, {"Administrador" if user.role == "admin" else "Usuario"}!', 'success')
                
                return redirect(url_for('dashboard'))
            
            # Credenciales inválidas
            flash('Credenciales inválidas', 'error')
            logger.warning(f"Intento de inicio de sesión fallido para {email}")
            return render_template('login.html')
            
        except Exception as e:
            logger.error(f"Error en el login: {str(e)}")
            flash('Error en el sistema. Por favor intenta más tarde.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Si es el primer usuario, asignar rol de admin
        user_count = User.query.count()
        role = 'admin' if user_count == 0 else 'user'

        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('El correo electrónico ya está registrado', 'error')
            return render_template('register.html')

        try:
            # Crear nuevo usuario
            user = User(email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            logger.info(f"Nuevo usuario registrado: {email} con rol {role}")
            flash('Registro exitoso. Por favor inicia sesión.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error en el registro: {str(e)}")
            flash('Error al crear el usuario', 'error')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Obtener datos de la sesión
        user_data = session.get('user')
        if not user_data:
            raise ValueError("No hay datos de usuario en la sesión")

        # Obtener el usuario de la base de datos para verificar que sigue existiendo
        user_db = User.query.get(user_data.get('id'))
        if not user_db:
            raise ValueError("Usuario no encontrado en la base de datos")

        # Verificar el rol y cargar los horarios correspondientes
        role = user_data.get('role', '').lower()
        if role == 'admin':
            # Administrador ve todos los horarios
            horarios = Horario.query.order_by(Horario.dia, Horario.hora_inicio).all()
            logger.info(f"Admin {user_data.get('email')} accedió al dashboard")
            return render_template('admin_dashboard.html', 
                                horarios=horarios, 
                                user=user_data)
        else:
            # Usuario normal solo ve sus horarios
            horarios = Horario.query.filter_by(
                docente=user_data.get('email')
            ).order_by(Horario.dia, Horario.hora_inicio).all()
            logger.info(f"Usuario {user_data.get('email')} accedió al dashboard")
            return render_template('user_dashboard.html', 
                                horarios=horarios, 
                                user=user_data)
            
    except Exception as e:
        logger.error(f"Error en el dashboard: {str(e)}")
        session.clear()
        flash('Ha ocurrido un error. Por favor inicia sesión nuevamente.', 'error')
        return redirect(url_for('login'))
            
    except Exception as e:
        logger.error(f"Error en el dashboard: {str(e)}")
        flash('Error al cargar los horarios', 'error')
        return redirect(url_for('login'))

@app.route('/horario/create', methods=['POST'])
@login_required
def create_horario():
    user = session.get('user', {})
    if user.get('role', '').lower() != 'admin':
        logger.warning(f"Usuario no autorizado {user.get('email')} intentó crear un horario")
        return jsonify({'error': 'No tienes permisos para realizar esta acción'}), 403

    try:
        data = request.get_json()
        if not all(key in data for key in ['dia', 'hora_inicio', 'hora_fin', 'materia', 'docente', 'salon']):
            return jsonify({'error': 'Faltan campos requeridos'}), 400
            
        hora_inicio = datetime.strptime(data['hora_inicio'], '%H:%M').time()
        hora_fin = datetime.strptime(data['hora_fin'], '%H:%M').time()

        horario = Horario(
            dia=data['dia'],
            hora_inicio=hora_inicio,
            hora_fin=hora_fin,
            materia=data['materia'],
            docente=data['docente'],
            salon=data['salon']
        )
        
        db.session.add(horario)
        db.session.commit()
        
        logger.info(f"Horario creado para {data['docente']}")
        return jsonify(horario.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al crear horario: {str(e)}")
        return jsonify({'error': 'Error al crear el horario'}), 500

@app.route('/horarios', methods=['GET'])
@login_required
def get_horarios():
    try:
        if session.get('user', {}).get('role') == 'admin':
            # Admins ven todos los horarios
            horarios = Horario.query.all()
        else:
            # Usuarios normales solo ven sus horarios
            horarios = Horario.query.filter_by(docente=session.get('user', {}).get('email')).all()
        
        return jsonify([h.to_dict() for h in horarios]), 200

    except Exception as e:
        logger.error(f"Error al obtener horarios: {str(e)}")
        return jsonify({'error': 'Error al obtener los horarios'}), 500

@app.route('/horario/<int:id>', methods=['PUT'])
@login_required
def update_horario(id):
    if session.get('user', {}).get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403

    try:
        horario = Horario.query.get_or_404(id)
        data = request.get_json()

        if 'hora_inicio' in data:
            horario.hora_inicio = datetime.strptime(data['hora_inicio'], '%H:%M').time()
        if 'hora_fin' in data:
            horario.hora_fin = datetime.strptime(data['hora_fin'], '%H:%M').time()
        if 'dia' in data:
            horario.dia = data['dia']
        if 'materia' in data:
            horario.materia = data['materia']
        if 'docente' in data:
            horario.docente = data['docente']
        if 'salon' in data:
            horario.salon = data['salon']

        db.session.commit()
        logger.info(f"Horario {id} actualizado")
        return jsonify(horario.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al actualizar horario: {str(e)}")
        return jsonify({'error': 'Error al actualizar el horario'}), 500

@app.route('/horario/<int:id>', methods=['DELETE'])
@login_required
def delete_horario(id):
    if session.get('user', {}).get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403

    try:
        horario = Horario.query.get_or_404(id)
        db.session.delete(horario)
        db.session.commit()
        
        logger.info(f"Horario {id} eliminado")
        return jsonify({'message': 'Horario eliminado'}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar horario: {str(e)}")
        return jsonify({'error': 'Error al eliminar el horario'}), 500

@app.route('/users')
@login_required
def list_users():
    if session.get('user', {}).get('role') != 'admin':
        flash('No tienes permiso para acceder a esta página', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/logout')
def logout():
    user_email = session.get('user', {}).get('email')
    if user_email:
        logger.info(f"Usuario {user_email} ha cerrado sesión")
    
    session.clear()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False').lower() == 'true', port=5001)