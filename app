from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import pyotp
import qrcode
from io import BytesIO
import base64
import uuid
import logging
from cryptography.fernet import Fernet
import functools

# App configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Setup database
db = SQLAlchemy(app)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Setup logging
logging.basicConfig(
    filename='hipaa_compliance.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hipaa_compliance')

# Encryption setup
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive data"""
    if data is None:
        return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(data):
    """Decrypt sensitive data"""
    if data is None:
        return None
    return cipher_suite.decrypt(data.encode()).decode()

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, doctor, nurse, patient
    totp_secret = db.Column(db.String(32))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="Healthcare App"
        )
    
    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    first_name_encrypted = db.Column(db.Text, nullable=False)
    last_name_encrypted = db.Column(db.Text, nullable=False)
    dob_encrypted = db.Column(db.Text, nullable=False)
    address_encrypted = db.Column(db.Text, nullable=False)
    phone_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def first_name(self):
        return decrypt_data(self.first_name_encrypted)
    
    @first_name.setter
    def first_name(self, value):
        self.first_name_encrypted = encrypt_data(value)
    
    @property
    def last_name(self):
        return decrypt_data(self.last_name_encrypted)
    
    @last_name.setter
    def last_name(self, value):
        self.last_name_encrypted = encrypt_data(value)
    
    @property
    def dob(self):
        return decrypt_data(self.dob_encrypted)
    
    @dob.setter
    def dob(self, value):
        self.dob_encrypted = encrypt_data(value)
    
    @property
    def address(self):
        return decrypt_data(self.address_encrypted)
    
    @address.setter
    def address(self, value):
        self.address_encrypted = encrypt_data(value)
    
    @property
    def phone(self):
        return decrypt_data(self.phone_encrypted)
    
    @phone.setter
    def phone(self, value):
        self.phone_encrypted = encrypt_data(value)

class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)
    diagnosis_encrypted = db.Column(db.Text, nullable=True)
    treatment_encrypted = db.Column(db.Text, nullable=True)
    notes_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def diagnosis(self):
        return decrypt_data(self.diagnosis_encrypted)
    
    @diagnosis.setter
    def diagnosis(self, value):
        self.diagnosis_encrypted = encrypt_data(value)
    
    @property
    def treatment(self):
        return decrypt_data(self.treatment_encrypted)
    
    @treatment.setter
    def treatment(self, value):
        self.treatment_encrypted = encrypt_data(value)
    
    @property
    def notes(self):
        return decrypt_data(self.notes_encrypted)
    
    @notes.setter
    def notes(self, value):
        self.notes_encrypted = encrypt_data(value)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    details = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for role-based access control
def role_required(roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# HIPAA compliance logging
def log_action(action, table_name, record_id, details=None):
    """Log actions for HIPAA compliance"""
    if current_user.is_authenticated:
        audit_log = AuditLog(
            user_id=current_user.id,
            action=action,
            table_name=table_name,
            record_id=record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            details=details
        )
        db.session.add(audit_log)
        db.session.commit()
        logger.info(f'Action logged: {action} on {table_name} with ID {record_id} by user {current_user.id}')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.totp_secret:
                # Store user ID in session for 2FA verification
                session['user_id_for_2fa'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                # If 2FA is not set up, log in directly
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Check if user has passed the first authentication factor
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user = User.query.get(session['user_id_for_2fa'])
        totp_code = request.form.get('totp_code')
        
        if user and user.verify_totp(totp_code):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            session.pop('user_id_for_2fa', None)
            flash('Two-factor authentication successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code', 'danger')
    
    return render_template('verify_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Create user
        user = User(username=username, email=email, totp_secret=totp_secret)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Store user ID for setup 2FA page
        session['user_id_for_2fa_setup'] = user.id
        
        flash('Registration successful! Please set up two-factor authentication.', 'success')
        return redirect(url_for('setup_2fa'))
    
    return render_template('register.html')

@app.route('/setup-2fa')
def setup_2fa():
    if 'user_id_for_2fa_setup' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id_for_2fa_setup'])
    
    if not user:
        session.pop('user_id_for_2fa_setup', None)
        return redirect(url_for('login'))
    
    # Generate QR code for TOTP
    totp_uri = user.get_totp_uri()
    qr = qrcode.make(totp_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('setup_2fa.html', qr_code=qr_code, secret=user.totp_secret)

@app.route('/complete-2fa-setup', methods=['POST'])
def complete_2fa_setup():
    if 'user_id_for_2fa_setup' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id_for_2fa_setup'])
    
    if not user:
        session.pop('user_id_for_2fa_setup', None)
        return redirect(url_for('login'))
    
    totp_code = request.form.get('totp_code')
    
    if user.verify_totp(totp_code):
        session.pop('user_id_for_2fa_setup', None)
        flash('Two-factor authentication set up successfully!', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid verification code. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Different dashboards based on user role
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html')
    elif current_user.role == 'doctor':
        patients = Patient.query.all()
        log_action('VIEW', 'Patient', 0, 'Listed all patients')
        return render_template('doctor_dashboard.html', patients=patients)
    elif current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        medical_records = []
        if patient:
            medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).all()
            log_action('VIEW', 'MedicalRecord', patient.id, 'Viewed own medical records')
        return render_template('patient_dashboard.html', patient=patient, medical_records=medical_records)
    else:
        return render_template('dashboard.html')

@app.route('/patient/<int:patient_id>')
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def view_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    medical_records = MedicalRecord.query.filter_by(patient_id=patient_id).all()
    
    log_action('VIEW', 'Patient', patient_id, f'Viewed patient details')
    return render_template('patient_detail.html', patient=patient, medical_records=medical_records)

@app.route('/patient/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor'])
def add_patient():
    if request.method == 'POST':
        try:
            patient = Patient()
            patient.first_name = request.form.get('first_name')
            patient.last_name = request.form.get('last_name')
            patient.dob = request.form.get('dob')
            patient.address = request.form.get('address')
            patient.phone = request.form.get('phone')
            
            db.session.add(patient)
            db.session.commit()
            
            log_action('CREATE', 'Patient', patient.id, 'Created new patient')
            
            flash('Patient added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding patient: {str(e)}', 'danger')
    
    return render_template('add_patient.html')

@app.route('/medical-record/add/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor'])
def add_medical_record(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        try:
            record = MedicalRecord(
                patient_id=patient_id,
                doctor_id=current_user.id,
                record_type=request.form.get('record_type')
            )
            record.diagnosis = request.form.get('diagnosis')
            record.treatment = request.form.get('treatment')
            record.notes = request.form.get('notes')
            
            db.session.add(record)
            db.session.commit()
            
            log_action('CREATE', 'MedicalRecord', record.id, f'Created medical record for patient {patient_id}')
            
            flash('Medical record added successfully!', 'success')
            return redirect(url_for('view_patient', patient_id=patient_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding medical record: {str(e)}', 'danger')
    
    return render_template('add_medical_record.html', patient=patient)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/init-db')
def init_db():
    """Initialize the database with sample data (for testing only)"""
    if not os.environ.get('ALLOW_DB_INIT'):
        return 'Not allowed in production', 403
    
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        admin.totp_secret = pyotp.random_base32()
        db.session.add(admin)
        
        # Create doctor user if not exists
        if not User.query.filter_by(username='doctor').first():
            doctor = User(username='doctor', email='doctor@example.com', role='doctor')
            doctor.set_password('doctor123')
            doctor.totp_secret = pyotp.random_base32()
            db.session.add(doctor)
        
        # Create patient user if not exists
        if not User.query.filter_by(username='patient').first():
            patient_user = User(username='patient', email='patient@example.com', role='patient')
            patient_user.set_password('patient123')
            patient_user.totp_secret = pyotp.random_base32()
            db.session.add(patient_user)
            
            # Add a patient record
            patient = Patient()
            patient.user_id = 3  # Will be the ID of the patient user
            patient.first_name = "John"
            patient.last_name = "Doe"
            patient.dob = "1980-01-01"
            patient.address = "123 Main St, Anytown, US"
            patient.phone = "555-123-4567"
            db.session.add(patient)
        
        db.session.commit()
        return 'Database initialized with sample data'
    
    return 'Database already initialized'

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Run the app with SSL (for development only)
    # In production, use a proper WSGI server with SSL termination
    app.run(debug=True, ssl_context='adhoc')
