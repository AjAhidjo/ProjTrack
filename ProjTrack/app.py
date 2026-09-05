import os
import time
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
# --- SocketIO Imports ---
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import CSRFProtect

# 1. Initialize App
app = Flask(__name__)

# 2. Configuration
# SECRET_KEY, MAIL_USERNAME, and MAIL_PASSWORD are read from environment variables
# instead of being hardcoded, so real credentials never end up in source control.
# Set these before running (see .env.example), e.g. in PowerShell:
#   $env:MAIL_USERNAME="you@gmail.com"; $env:MAIL_PASSWORD="your-16-char-app-password"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-fallback-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'pdf'}
PROJECT_CHAPTERS = ['Chapter 1', 'Chapter 2', 'Chapter 3', 'Chapter 4', 'Chapter 5', 'Final Project']

# 3. Email Settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# 4. Initialize Extensions
db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
# Initialize SocketIO with eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


from flask_wtf.csrf import CSRFError


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Your session expired or the form was submitted incorrectly. Please try again.', 'danger')
    return redirect(request.referrer or url_for('index'))


# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    supervisor = db.relationship('User', remote_side=[id], backref='students')
    projects = db.relationship('Project', backref='owner', lazy=True, cascade="all, delete-orphan")


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    chapter = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default='Under Review')
    comment = db.Column(db.Text)
    file_path = db.Column(db.String(300))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.Float, default=time.time)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    is_edited = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Custom Filter ---
@app.template_filter('datetimeformat')
def datetimeformat(value):
    if value:
        return datetime.fromtimestamp(value).strftime('%d %b, %Y | %I:%M %p')
    return "N/A"


# --- Access Control ---
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("Access Denied!")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def can_message(user_a, user_b_id):
    """Only allow chat between a student and their own assigned supervisor (in either direction)."""
    if user_a.role == 'student':
        return user_a.supervisor_id == user_b_id
    if user_a.role == 'supervisor':
        other = User.query.get(user_b_id)
        return other is not None and other.supervisor_id == user_a.id
    return False


# --- Authentication Routes ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    template_map = {'student': 'login_student.html', 'supervisor': 'login_supervisor.html'}
    if role not in template_map: abort(404)

    if request.method == 'POST':
        csrf.protect()
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            if user.role != role:
                flash(f'Unauthorized access to {role} portal.', 'danger')
                return redirect(url_for('login', role=role))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template(template_map[role], role=role)


@app.route('/management-access-only', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        csrf.protect()
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            if user.role == 'admin':
                login_user(user)
                return redirect(url_for('admin_panel'))
            flash('Unauthorized!', 'danger')
        else:
            flash('Invalid Admin Credentials', 'danger')
    return render_template('login_admin.html', role='admin')


@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        csrf.protect()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip() or None
        if User.query.filter_by(username=username).first():
            flash('Username taken!', 'danger')
            return redirect(url_for('register_student'))
        if email and User.query.filter_by(email=email).first():
            flash('An account with that email already exists!', 'danger')
            return redirect(url_for('register_student'))

        new_user = User(username=username, email=email,
                        full_name=request.form['full_name'],
                        password=generate_password_hash(request.form['password']), role='student')
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('That username or email is already registered.', 'danger')
            return redirect(url_for('register_student'))
        flash('Student account created!', 'success')
        return redirect(url_for('login', role='student'))
    return render_template('register_student.html')


@app.route('/register/supervisor', methods=['GET', 'POST'])
def register_supervisor():
    if request.method == 'POST':
        csrf.protect()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip() or None
        if User.query.filter_by(username=username).first():
            flash('Staff ID taken!', 'danger')
            return redirect(url_for('register_supervisor'))
        if email and User.query.filter_by(email=email).first():
            flash('An account with that email already exists!', 'danger')
            return redirect(url_for('register_supervisor'))

        new_user = User(username=username, email=email,
                        full_name=request.form['full_name'],
                        password=generate_password_hash(request.form['password']), role='supervisor')
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('That username or email is already registered.', 'danger')
            return redirect(url_for('register_supervisor'))
        flash('Supervisor account created!', 'success')
        return redirect(url_for('login', role='supervisor'))
    return render_template('register_supervisor.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# --- Dashboard Logic ---

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin': return redirect(url_for('admin_panel'))
    if current_user.role == 'student':
        projects = Project.query.filter_by(student_id=current_user.id).all()
        my_supervisor = User.query.get(current_user.supervisor_id) if current_user.supervisor_id else None
        approved_count = Project.query.filter_by(student_id=current_user.id, status='Approved').count()
        progress_val = min(100, int((approved_count / len(PROJECT_CHAPTERS)) * 100))
        unread_count = ChatMessage.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        return render_template('dashboard.html', projects=projects, supervisor=my_supervisor, progress=progress_val,
                               unread_count=unread_count)

    if current_user.role == 'supervisor':
        my_students = User.query.filter_by(supervisor_id=current_user.id).all()
        student_ids = [s.id for s in my_students]
        assigned_data = db.session.query(Project, User).join(User, Project.student_id == User.id) \
            .filter(Project.student_id.in_(student_ids)).order_by(Project.timestamp.desc()).all()
        unread_map = {
            s.id: ChatMessage.query.filter_by(sender_id=s.id, recipient_id=current_user.id, is_read=False).count() for s
            in my_students}
        return render_template('dashboard.html', assigned_data=assigned_data, my_students=my_students,
                               unread_map=unread_map)


@app.route('/upload', methods=['POST'])
@login_required
@role_required('student')
def upload():
    csrf.protect()
    file = request.files.get('file')
    chapter = request.form.get('chapter')
    title = request.form.get('title', '').strip()

    if not chapter or chapter not in PROJECT_CHAPTERS:
        flash('Please select a valid chapter.', 'danger')
        return redirect(url_for('dashboard'))

    if not title:
        flash('Please enter a research topic/title.', 'danger')
        return redirect(url_for('dashboard'))

    if not file or file.filename == '':
        flash('Please choose a file to upload.', 'danger')
        return redirect(url_for('dashboard'))

    if not allowed_file(file.filename):
        flash('Invalid file type. Only PDF files are accepted.', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    unique_name = f"user_{current_user.id}_{int(time.time())}_{filename}"
    existing_project = Project.query.filter_by(student_id=current_user.id, chapter=chapter).first()

    if existing_project:
        old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_project.file_path)
        if os.path.exists(old_file_path):
            try:
                os.remove(old_file_path)
            except OSError:
                pass
        existing_project.title = title
        existing_project.file_path = unique_name
        existing_project.status = 'Under Review'
        existing_project.timestamp = time.time()
        db.session.commit()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
        flash(f'{chapter} updated!', 'success')
    else:
        new_p = Project(title=title, student_id=current_user.id, chapter=chapter, file_path=unique_name)
        db.session.add(new_p)
        db.session.commit()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
        flash(f'{chapter} submitted!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/review', methods=['POST'])
@login_required
@role_required('supervisor')
def review_project():
    csrf.protect()
    pid = request.form.get('project_id')
    proj = Project.query.get_or_404(pid)
    student = User.query.get(proj.student_id)
    if not student or student.supervisor_id != current_user.id:
        flash("You can only review your own students' submissions.", 'danger')
        return redirect(url_for('dashboard'))

    status = request.form.get('status')
    if status not in ('Approved', 'Correction Needed'):
        flash('Invalid status.', 'danger')
        return redirect(url_for('dashboard'))

    proj.status = status
    proj.comment = request.form.get('comment')
    db.session.commit()
    flash('Review saved', 'success')
    return redirect(url_for('dashboard'))


@app.route('/view/<path:filename>')
@login_required
def view_file(filename):
    proj = Project.query.filter_by(file_path=filename).first()
    if not proj:
        abort(404)

    is_owner = proj.student_id == current_user.id
    is_their_supervisor = False
    if current_user.role == 'supervisor':
        student = User.query.get(proj.student_id)
        is_their_supervisor = student is not None and student.supervisor_id == current_user.id

    if not (is_owner or is_their_supervisor or current_user.role == 'admin'):
        abort(403)

    try:
        response = send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False,
                                       mimetype='application/pdf', conditional=True)
        response.headers["Content-Disposition"] = "inline"
        return response
    except FileNotFoundError:
        abort(404)


# --- Chat Logic ---

@app.route('/chat')
@app.route('/chat/<int:recipient_id>')
@login_required
def chat(recipient_id=None):
    my_students = User.query.filter_by(supervisor_id=current_user.id).all() if current_user.role == 'supervisor' else []
    messages = []
    recipient = None

    if not recipient_id and current_user.role == 'student' and current_user.supervisor_id:
        return redirect(url_for('chat', recipient_id=current_user.supervisor_id))

    if recipient_id:
        recipient = User.query.get_or_404(recipient_id)
        if not can_message(current_user, recipient_id):
            flash("You're not allowed to message this user.", 'danger')
            return redirect(url_for('chat'))
        ChatMessage.query.filter_by(sender_id=recipient_id, recipient_id=current_user.id, is_read=False).update(
            {ChatMessage.is_read: True})
        db.session.commit()
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.recipient_id == recipient_id)) |
            ((ChatMessage.sender_id == recipient_id) & (ChatMessage.recipient_id == current_user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('chat.html', recipient=recipient, messages=messages, my_students=my_students)


# --- SocketIO Events ---

@socketio.on('join')
def on_join(data):
    join_room(str(current_user.id))


@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    recipient_id = int(data['recipient_id'])
    if not can_message(current_user, recipient_id):
        return
    msg = ChatMessage(sender_id=current_user.id, recipient_id=recipient_id, content=data['message'])
    db.session.add(msg)
    db.session.commit()

    msg_data = {
        'id': msg.id, 'content': msg.content, 'sender_id': current_user.id,
        'full_name': current_user.full_name, 'timestamp': msg.timestamp.strftime('%I:%M %p')
    }
    emit('receive_message', msg_data, room=str(recipient_id))
    emit('receive_message', msg_data, room=str(current_user.id))


@socketio.on('edit_message')
def handle_edit_message(data):
    msg = ChatMessage.query.get(data['message_id'])
    if msg and msg.sender_id == current_user.id:
        msg.content = data['new_content']
        msg.is_edited = True
        db.session.commit()
        update_data = {'id': msg.id, 'new_content': msg.content}
        emit('message_edited', update_data, room=str(msg.recipient_id))
        emit('message_edited', update_data, room=str(msg.sender_id))


@socketio.on('delete_message')
def handle_delete_message(data):
    msg = ChatMessage.query.get(data['message_id'])
    if msg and msg.sender_id == current_user.id:
        recipient_id = msg.recipient_id
        db.session.delete(msg)
        db.session.commit()
        emit('message_deleted', {'id': data['message_id']}, room=str(recipient_id))
        emit('message_deleted', {'id': data['message_id']}, room=str(current_user.id))


# --- Admin Panel & Management ---

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    all_users = User.query.all()
    supervisors = User.query.filter_by(role='supervisor').all()
    students = User.query.filter_by(role='student').all() # FIXED: Added student filtering
    return render_template('admin.html', all_users=all_users, supervisors=supervisors, students=students)


@app.route('/assign', methods=['POST'])
@login_required
@role_required('admin')
def assign_supervisor():
    csrf.protect()
    student_id = request.form.get('student_id')
    supervisor_id = request.form.get('supervisor_id')
    student = User.query.get(student_id)
    if student:
        student.supervisor_id = supervisor_id
        db.session.commit()
        flash('Assigned successfully.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-user/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(id):
    csrf.protect()
    user = User.query.get_or_404(id)
    if user.id != current_user.id:
        if user.role == 'supervisor':
            # Unassign any students who had this supervisor, instead of leaving
            # their supervisor_id pointing at a user that no longer exists.
            for student in User.query.filter_by(supervisor_id=user.id).all():
                student.supervisor_id = None

        # Remove this user's uploaded files from disk (the DB rows for their
        # projects are removed automatically via the cascade on User.projects).
        for proj in Project.query.filter_by(student_id=user.id).all():
            if proj.file_path:
                path = os.path.join(app.config['UPLOAD_FOLDER'], proj.file_path)
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

        # Chat messages aren't linked via a cascading relationship, so clear
        # them out explicitly to avoid leaving rows that reference a deleted user.
        ChatMessage.query.filter(
            (ChatMessage.sender_id == user.id) | (ChatMessage.recipient_id == user.id)
        ).delete(synchronize_session=False)

        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('You cannot delete yourself!', 'danger')
    return redirect(url_for('admin_panel'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        csrf.protect()
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, old_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# --- Forgot / Reset Password ---

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        csrf.protect()
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()
        # Always show the same message, whether or not the email exists,
        # so we don't leak which addresses are registered.
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                msg = Message('ProjTrack Password Reset', sender=app.config['MAIL_USERNAME'],
                              recipients=[email])
                msg.body = (f"Hello {user.full_name},\n\n"
                            f"Click the link below to reset your ProjTrack password. "
                            f"This link expires in 30 minutes.\n\n{reset_url}\n\n"
                            f"If you didn't request this, you can ignore this email.")
                mail.send(msg)
            except Exception:
                # Email sending failed (bad SMTP config, offline, etc). Don't crash the request.
                pass
        flash('If that email is registered, a reset link has been sent.', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=1800)  # 30 minutes
    except Exception:
        flash('That reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('That reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        csrf.protect()
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not new_password or new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated. You can now log in.', 'success')
        return redirect(url_for('login', role=user.role)) if user.role in ('student', 'supervisor') else redirect(url_for('index'))

    return render_template('reset_password.html', email=email)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            default_admin_password = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'admin123')
            admin = User(username='admin', full_name='Administrator',
                         password=generate_password_hash(default_admin_password), role='admin')
            db.session.add(admin)
            db.session.commit()

    # DEBUG=1 (default) for local development — auto-reload, detailed error pages.
    # Set DEBUG=0 in your production environment; debug mode must never run on a public server.
    debug_mode = os.environ.get('DEBUG', '1') == '1'
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))

    if not debug_mode and app.config['SECRET_KEY'] == 'dev-only-fallback-key-change-me':
        print('WARNING: Running without DEBUG=1 but SECRET_KEY is not set. '
              'Set the SECRET_KEY environment variable before deploying.')

    socketio.run(app, debug=debug_mode, host=host, port=port)