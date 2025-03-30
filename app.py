from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta
import os
import pyotp
import qrcode
from io import BytesIO
import base64
import uuid
import logging
import traceback
from cryptography.fernet import Fernet
import functools
import ssl
import secrets

# App configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Secure cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Fix for proper HTTPS handling behind proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

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

# Encryption setup with improved key management
def get_or_create_encryption_key():
    """Get encryption key from environment or create and store it in a file"""
    key_from_env = os.environ.get('ENCRYPTION_KEY')
    
    if key_from_env:
        # Use the key from environment variable if available
        if isinstance(key_from_env, str):
            try:
                return base64.urlsafe_b64decode(key_from_env.encode())
            except:
                logger.error("Invalid ENCRYPTION_KEY format in environment variable")
                raise ValueError("ENCRYPTION_KEY must be a valid base64-encoded string")
        return key_from_env
    
    # Key file path
    key_file = os.path.join(os.getcwd(), 'instance', 'encryption.key')
    
    # Ensure the instance directory exists
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    
    # Check if key file exists
    if os.path.exists(key_file):
        # Read existing key
        with open(key_file, 'rb') as f:
            key_data = f.read()
            try:
                return base64.urlsafe_b64decode(key_data)
            except:
                logger.error("Invalid encryption key format in key file")
                # Generate new key if the existing one is invalid
                os.remove(key_file)
                return get_or_create_encryption_key()
    else:
        # Generate a new key
        key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        
        # Save the key to file with restricted permissions
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # Set permissions on key file (Unix/Linux only)
        try:
            os.chmod(key_file, 0o600)  # Only owner can read/write
        except:
            pass  # Ignore on Windows
            
        return base64.urlsafe_b64decode(key)

# Initialize encryption key
ENCRYPTION_KEY = get_or_create_encryption_key()
cipher_suite = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY))

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

# SSL Certificate Generation
def generate_self_signed_cert():
    """Generate a self-signed certificate for development HTTPS"""
    cert_dir = os.path.join(os.getcwd(), 'certificates')
    cert_file = os.path.join(cert_dir, 'cert.pem')
    key_file = os.path.join(cert_dir, 'key.pem')
    
    # If certificates already exist, return their paths
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    # Ensure certificates directory exists
    os.makedirs(cert_dir, exist_ok=True)
    
    # Generate certificates using OpenSSL command
    try:
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Healthcare App"
        cert.get_subject().OU = "IT Department"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years validity
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Write the certificate and private key to files
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        # Set permissions on key file (Unix/Linux only)
        try:
            os.chmod(key_file, 0o600)  # Only owner can read/write
        except:
            pass  # Ignore on Windows
            
        return cert_file, key_file
        
    except ImportError:
        logger.error("PyOpenSSL not installed. Cannot generate certificates automatically.")
        return None, None
    except Exception as e:
        logger.error(f"Error generating certificates: {e}")
        return None, None

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

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    # Enable HTTP Strict Transport Security (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Help prevent XSS
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Basic Content Security Policy
    csp = ("default-src 'self'; "
           "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
           "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
           "font-src 'self' https://cdnjs.cloudflare.com; "
           "img-src 'self' data:; "
           "frame-src 'self'")
    response.headers['Content-Security-Policy'] = csp
    
    return response

# Force HTTPS
@app.before_request
def redirect_to_https():
    """Redirect HTTP requests to HTTPS"""
    # Only when not in debug mode and not already HTTPS
    if not app.debug and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

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
                
                # Log the successful login
                log_action('LOGIN', 'User', user.id, 'Direct login successful')
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        else:
            # Log failed login attempt
            logger.warning(f'Failed login attempt for username: {username} from IP: {request.remote_addr}')
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
            
            # Log the successful 2FA login
            log_action('LOGIN', 'User', user.id, '2FA login successful')
            
            flash('Two-factor authentication successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed 2FA attempt
            if user:
                logger.warning(f'Failed 2FA attempt for user: {user.username} from IP: {request.remote_addr}')
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
        
        # Log new user registration
        logger.info(f'New user registered: {username} (ID: {user.id}) from IP: {request.remote_addr}')
        
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
        
        # Log successful 2FA setup
        logger.info(f'User {user.username} (ID: {user.id}) completed 2FA setup')
        
        flash('Two-factor authentication set up successfully!', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid verification code. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get current datetime for templates
    current_datetime = datetime.now()
    
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html', now=current_datetime, timedelta=timedelta)
    elif current_user.role == 'doctor':
        patients = Patient.query.all()
        log_action('VIEW', 'Patient', 0, 'Listed all patients')
        return render_template('doctor_dashboard.html', patients=patients, now=current_datetime)
    elif current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        medical_records = []
        if patient:
            medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).all()
            log_action('VIEW', 'MedicalRecord', patient.id, 'Viewed own medical records')
        return render_template('patient_dashboard.html', patient=patient, medical_records=medical_records, now=current_datetime)
    else:
        return render_template('dashboard.html', now=current_datetime)

@app.route('/patient/<int:patient_id>')
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def view_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    medical_records = MedicalRecord.query.filter_by(patient_id=patient_id).all()
    
    log_action('VIEW', 'Patient', patient_id, f'Viewed patient details')
    return render_template('patient_detail.html', patient=patient, medical_records=medical_records, now=datetime.now())

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
            logger.error(f'Error adding patient: {str(e)}\n{traceback.format_exc()}')
            flash(f'Error adding patient: {str(e)}', 'danger')
    
    return render_template('add_patient.html', now=datetime.now())

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
            logger.error(f'Error adding medical record: {str(e)}\n{traceback.format_exc()}')
            flash(f'Error adding medical record: {str(e)}', 'danger')
    
    return render_template('add_medical_record.html', patient=patient, now=datetime.now())

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    user_name = current_user.username
    logout_user()
    
    # Log the logout action
    logger.info(f'User logged out: {user_name} (ID: {user_id}) from IP: {request.remote_addr}')
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', now=datetime.now())

@app.route('/init-db')
def init_db():
    """Initialize the database with sample data and disable 2FA for testing"""
    try:
        # Don't check for ALLOW_DB_INIT to make debugging easier
        # if not os.environ.get('ALLOW_DB_INIT'):
        #     return 'Not allowed in production. Set ALLOW_DB_INIT environment variable to use this route.', 403
        
        # Create database tables
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            # Disable 2FA for testing by setting totp_secret to None
            admin.totp_secret = None
            db.session.add(admin)
        else:
            # Update existing admin to disable 2FA
            admin.totp_secret = None
            
        # Create doctor user if not exists
        doctor = User.query.filter_by(username='doctor').first()
        if not doctor:
            doctor = User(username='doctor', email='doctor@example.com', role='doctor')
            doctor.set_password('doctor123')
            # Disable 2FA for testing
            doctor.totp_secret = None
            db.session.add(doctor)
        else:
            # Update existing doctor to disable 2FA
            doctor.totp_secret = None
        
        # Create patient user if not exists
        patient_user = User.query.filter_by(username='patient').first()
        if not patient_user:
            patient_user = User(username='patient', email='patient@example.com', role='patient')
            patient_user.set_password('patient123')
            # Disable 2FA for testing
            patient_user.totp_secret = None
            db.session.add(patient_user)
        else:
            # Update existing patient to disable 2FA
            patient_user.totp_secret = None
            
        # Add a patient record if it doesn't exist
        db.session.commit()  # Commit to get IDs
        
        patient = Patient.query.filter_by(user_id=patient_user.id).first()
        if not patient:
            patient = Patient()
            patient.user_id = patient_user.id
            patient.first_name = "John"
            patient.last_name = "Doe"
            patient.dob = "1980-01-01"
            patient.address = "123 Main St, Anytown, US"
            patient.phone = "555-123-4567"
            db.session.add(patient)
        
        # Commit all changes
        db.session.commit()

        # Determine the port for the proper link
        port = "8443" if os.path.exists(os.path.join(os.getcwd(), 'certificates', 'cert.pem')) else "8080"
        protocol = "https" if port == "8443" else "http"

        return f'''
        <h1>Database initialized with sample data</h1>
        <p>Users created with 2FA disabled for testing:</p>
        <ul>
            <li><strong>Admin:</strong> username=admin, password=admin123</li>
            <li><strong>Doctor:</strong> username=doctor, password=doctor123</li>
            <li><strong>Patient:</strong> username=patient, password=patient123</li>
        </ul>
        <p><a href="{protocol}://localhost:{port}/login">Go to login page</a></p>
        <p><small>Note: The application is running on port {port} with {protocol.upper()}</small></p>
        '''
    except Exception as e:
        # Return debug information
        error_traceback = traceback.format_exc()
        return f'''
        <h1>Error initializing database</h1>
        <p>Error: {str(e)}</p>
        <pre>{error_traceback}</pre>
        '''

@app.route('/debug')
def debug_info():
    """Debug information route for development only"""
    info = {
        "Python version": os.sys.version,
        "Flask version": Flask.__version__,
        "Database URI": app.config['SQLALCHEMY_DATABASE_URI'],
        "Secret Key Set": bool(app.config['SECRET_KEY']),
        "Working Directory": os.getcwd(),
        "Templates Folder": os.path.isdir(os.path.join(os.getcwd(), 'templates')),
        "Static Folder": os.path.isdir(os.path.join(os.getcwd(), 'static')),
        "HTTPS Enabled": os.path.exists(os.path.join(os.getcwd(), 'certificates', 'cert.pem')),
        "Encryption Key Source": "Environment" if os.environ.get('ENCRYPTION_KEY') else "File",
        "Environment Variables": {k: "[REDACTED]" for k in ['FLASK_APP', 'FLASK_ENV', 'SECRET_KEY', 'ENCRYPTION_KEY']}
    }
    
    return jsonify(info)

# Add a route to check the encryption status
@app.route('/encryption-check')
@login_required
@role_required(['admin'])
def encryption_check():
    """Check encryption status for admins"""
    try:
        # Test encryption and decryption
        test_data = "ENCRYPTION_TEST_" + secrets.token_hex(8)
        encrypted = encrypt_data(test_data)
        decrypted = decrypt_data(encrypted)
        
        encryption_ok = (test_data == decrypted)
        
        # Get key info
        key_source = "Environment variable" if os.environ.get('ENCRYPTION_KEY') else "Local file"
        key_file = os.path.join(os.getcwd(), 'instance', 'encryption.key')
        key_file_exists = os.path.exists(key_file)
        
        # Certificates info
        cert_file = os.path.join(os.getcwd(), 'certificates', 'cert.pem')
        key_file_ssl = os.path.join(os.getcwd(), 'certificates', 'key.pem')
        ssl_configured = os.path.exists(cert_file) and os.path.exists(key_file_ssl)
        
        # Get audit log count
        audit_log_count = AuditLog.query.count()
        
        return jsonify({
            "encryption_status": "OK" if encryption_ok else "FAILED",
            "encryption_key_source": key_source,
            "key_file_exists": key_file_exists,
            "ssl_configured": ssl_configured,
            "https_enabled": request.is_secure,
            "audit_log_count": audit_log_count,
            "security_headers": {
                "HSTS": "Enabled",
                "CSP": "Enabled",
                "XSS-Protection": "Enabled",
                "Content-Type-Options": "Enabled",
                "Frame-Options": "Enabled"
            }
        })
    except Exception as e:
        return jsonify({
            "encryption_status": "ERROR",
            "error": str(e)
        }), 500

# Security breach detection
@app.before_request
def detect_security_breaches():
    """Detect potential security breaches"""
    # Check for suspicious user agents
    user_agent = request.headers.get('User-Agent', '').lower()
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'dirbuster', 'metasploit']
    
    if any(agent in user_agent for agent in suspicious_agents):
        logger.warning(f"Potential security scan detected: {request.remote_addr} - {user_agent}")
        
    # Check for SQL injection attempts in parameters
    sql_patterns = ["'--", "DROP TABLE", "1=1", "OR 1=1", "UNION SELECT", ";--"]
    for key, value in request.values.items():
        if isinstance(value, str) and any(pattern.lower() in value.lower() for pattern in sql_patterns):
            logger.warning(f"Potential SQL injection: {request.remote_addr} - {key}={value}")
            return "Invalid request", 403

# Error handlers for improved security (don't leak information)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Generate SSL certificates if needed
    cert_file, key_file = generate_self_signed_cert()
    
    # Check if certificates are available
    if cert_file and key_file:
        # Run with HTTPS on port 8443
        print("Running with HTTPS on port 8443")
        # For production, set debug=False
        app.run(debug=True, host='0.0.0.0', port=8443, 
                ssl_context=(cert_file, key_file))
    else:
        # Fallback to HTTP (not recommended for production)
        print("WARNING: Running without HTTPS! Install PyOpenSSL for secure HTTPS.")
        print("Install with: pip install pyopenssl")
        app.run(debug=True, host='0.0.0.0', port=8080)
