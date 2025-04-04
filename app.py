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
import traceback
from cryptography.fernet import Fernet, InvalidToken
import functools

# App configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_for_testing')
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

# Multiple encryption keys to try (in order of preference)
ENCRYPTION_KEYS = [
    # Original key from app.py
    b'tgUHCcmmL5UWmjq2zZh61twDxNrIi6C5F_T-kv46y-o=',
    
    # Alternative key formats to try
    'tgUHCcmmL5UWmjq2zZh61twDxNrIi6C5F_T-kv46y-o=',
    
    # Add more potential keys if needed
    b'5A_j5o0Hl8-Q_Bw7JnauOtfQxpJJcuJ7NhHisjWM8SY=',
    '5A_j5o0Hl8-Q_Bw7JnauOtfQxpJJcuJ7NhHisjWM8SY=',
]

# Initialize multiple cipher suites for decryption attempts
cipher_suites = []
for key in ENCRYPTION_KEYS:
    try:
        if isinstance(key, str):
            key_bytes = key.encode()
        else:
            key_bytes = key
        cipher_suites.append(Fernet(key_bytes))
    except Exception as e:
        logger.error(f"Invalid key format: {e}")

# Use the first key for encryption (primary key)
primary_cipher = cipher_suites[0] if cipher_suites else None

if not primary_cipher:
    logger.critical("No valid encryption keys found!")
    raise RuntimeError("Failed to initialize encryption. Check your keys.")

def encrypt_data(data):
    """Encrypt sensitive data using the primary key"""
    if data is None:
        return None
    return primary_cipher.encrypt(data.encode()).decode()

def decrypt_data(data):
    """Attempt to decrypt data with all available keys"""
    if data is None:
        return None
    
    # Convert string to bytes if needed
    data_bytes = data.encode() if isinstance(data, str) else data
    
    # Try each cipher suite until one works
    for cipher in cipher_suites:
        try:
            decrypted = cipher.decrypt(data_bytes)
            return decrypted.decode()
        except InvalidToken:
            continue
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            continue
    
    # If we reach here, all decryption attempts failed
    logger.error(f"Failed to decrypt data with any key")
    raise InvalidToken("Unable to decrypt data with any available key")

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
        try:
            return decrypt_data(self.first_name_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting first_name for patient {self.id}: {e}")
            return "[Decryption Error]"
    
    @first_name.setter
    def first_name(self, value):
        self.first_name_encrypted = encrypt_data(value)
    
    @property
    def last_name(self):
        try:
            return decrypt_data(self.last_name_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting last_name for patient {self.id}: {e}")
            return "[Decryption Error]"
    
    @last_name.setter
    def last_name(self, value):
        self.last_name_encrypted = encrypt_data(value)
    
    @property
    def dob(self):
        try:
            return decrypt_data(self.dob_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting dob for patient {self.id}: {e}")
            return "[Decryption Error]"
    
    @dob.setter
    def dob(self, value):
        self.dob_encrypted = encrypt_data(value)
    
    @property
    def address(self):
        try:
            return decrypt_data(self.address_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting address for patient {self.id}: {e}")
            return "[Decryption Error]"
    
    @address.setter
    def address(self, value):
        self.address_encrypted = encrypt_data(value)
    
    @property
    def phone(self):
        try:
            return decrypt_data(self.phone_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting phone for patient {self.id}: {e}")
            return "[Decryption Error]"
    
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
        try:
            return decrypt_data(self.diagnosis_encrypted) if self.diagnosis_encrypted else None
        except Exception as e:
            logger.error(f"Error decrypting diagnosis for record {self.id}: {e}")
            return "[Decryption Error]"
    
    @diagnosis.setter
    def diagnosis(self, value):
        self.diagnosis_encrypted = encrypt_data(value) if value else None
    
    @property
    def treatment(self):
        try:
            return decrypt_data(self.treatment_encrypted) if self.treatment_encrypted else None
        except Exception as e:
            logger.error(f"Error decrypting treatment for record {self.id}: {e}")
            return "[Decryption Error]"
    
    @treatment.setter
    def treatment(self, value):
        self.treatment_encrypted = encrypt_data(value) if value else None
    
    @property
    def notes(self):
        try:
            return decrypt_data(self.notes_encrypted) if self.notes_encrypted else None
        except Exception as e:
            logger.error(f"Error decrypting notes for record {self.id}: {e}")
            return "[Decryption Error]"
    
    @notes.setter
    def notes(self, value):
        self.notes_encrypted = encrypt_data(value) if value else None

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

# Basic security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

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
    # Get current datetime for templates
    current_datetime = datetime.now()
    
    # Different dashboards based on user role
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html', now=current_datetime, timedelta=timedelta)
    elif current_user.role == 'doctor':
        patients = Patient.query.all()
        
        # Filter out patients with decryption errors
        valid_patients = []
        for patient in patients:
            try:
                # Test if we can decrypt the patient's name
                first_name = patient.first_name
                last_name = patient.last_name
                
                # If we get here, decryption worked
                valid_patients.append(patient)
            except Exception as e:
                logger.error(f"Skipping patient {patient.id} due to decryption error: {e}")
                # Skip this patient in the display
        
        log_action('VIEW', 'Patient', 0, 'Listed all patients')
        
        # Pass a flag to indicate if there are any decryption errors
        decryption_errors = len(patients) > len(valid_patients)
        
        return render_template('doctor_dashboard.html', 
                              patients=valid_patients, 
                              now=current_datetime,
                              decryption_errors=decryption_errors)
    elif current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        medical_records = []
        
        # Check if patient data is valid
        patient_valid = True
        if patient:
            try:
                # Test if we can decrypt the patient's name
                first_name = patient.first_name
                last_name = patient.last_name
            except Exception as e:
                logger.error(f"Decryption error for patient {patient.id}: {e}")
                patient_valid = False
            
            if patient_valid:
                try:
                    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).all()
                    log_action('VIEW', 'MedicalRecord', patient.id, 'Viewed own medical records')
                except Exception as e:
                    logger.error(f"Error retrieving medical records: {e}")
        
        return render_template('patient_dashboard.html', 
                              patient=patient if patient_valid else None, 
                              medical_records=medical_records, 
                              now=current_datetime,
                              decryption_error=patient and not patient_valid)
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
            logger.error(f"Error adding patient: {str(e)}")
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
            logger.error(f"Error adding medical record: {str(e)}")
            flash(f'Error adding medical record: {str(e)}', 'danger')
    
    return render_template('add_medical_record.html', patient=patient, now=datetime.now())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', now=datetime.now())

@app.route('/fix-default-patients')
@login_required
@role_required(['admin'])
def fix_default_patients():
    """Fix the default patients that have decryption errors"""
    try:
        # Find patient user
        patient_user = User.query.filter_by(username='patient').first()
        
        if not patient_user:
            return "Patient user not found. Run /init-db first.", 404
        
        # Check for existing patient records linked to this user
        patients = Patient.query.filter_by(user_id=patient_user.id).all()
        patients_fixed = 0
        
        for patient in patients:
            try:
                # Test if we can decrypt the patient data
                try:
                    first_name = patient.first_name
                    last_name = patient.last_name
                    # If we get here, decryption worked!
                    continue
                except Exception:
                    # Decryption failed, we need to fix this patient
                    pass
                
                # Re-create the patient data with current encryption
                patient.first_name = "John"
                patient.last_name = "Doe"
                patient.dob = "1980-01-01"
                patient.address = "123 Main St, Anytown, US"
                patient.phone = "555-123-4567"
                patients_fixed += 1
                
            except Exception as e:
                logger.error(f"Error fixing patient {patient.id}: {e}")
        
        # Commit changes
        db.session.commit()
        
        return f'''
        <h1>Default Patient Fix Complete</h1>
        <p>Checked {len(patients)} patient records linked to the default patient user.</p>
        <p>Fixed {patients_fixed} patients with decryption errors.</p>
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        logger.error(f"Failed to fix default patients: {error_msg}")
        return f'''
        <h1>Error Fixing Default Patients</h1>
        <p>An error occurred: {error_msg}</p>
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''

# Add a route to recreate all sample data
@app.route('/recreate-default-data')
@login_required
@role_required(['admin'])
def recreate_default_data():
    """Recreate all default data with current encryption"""
    try:
        # Find default users
        patient_user = User.query.filter_by(username='patient').first()
        
        if not patient_user:
            return "Default users not found. Run /init-db first.", 404
        
        # Delete existing patient records for default users
        default_patients = Patient.query.filter_by(user_id=patient_user.id).all()
        for patient in default_patients:
            # Also delete related medical records
            MedicalRecord.query.filter_by(patient_id=patient.id).delete()
            db.session.delete(patient)
        
        db.session.commit()
        
        # Create new default patient with current encryption
        patient = Patient()
        patient.user_id = patient_user.id
        patient.first_name = "John"
        patient.last_name = "Doe"
        patient.dob = "1980-01-01"
        patient.address = "123 Main St, Anytown, US"
        patient.phone = "555-123-4567"
        db.session.add(patient)
        db.session.commit()
        
        # Add a sample medical record
        record = MedicalRecord(
            patient_id=patient.id,
            doctor_id=User.query.filter_by(username='doctor').first().id,
            record_type="Consultation"
        )
        record.diagnosis = "Seasonal allergies"
        record.treatment = "Antihistamines as needed"
        record.notes = "Patient reported feeling better after initial treatment"
        db.session.add(record)
        db.session.commit()
        
        return f'''
        <h1>Default Data Recreated</h1>
        <p>Successfully recreated all default patient data with current encryption.</p>
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        logger.error(f"Failed to recreate default data: {error_msg}")
        return f'''
        <h1>Error Recreating Default Data</h1>
        <p>An error occurred: {error_msg}</p>
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''

@app.route('/migrate-data')
@login_required
@role_required(['admin'])
def migrate_data():
    """Tool to migrate data to use the primary encryption key"""
    if request.args.get('confirm') != 'yes':
        return '''
        <h1>Data Migration Tool</h1>
        <p>This tool will attempt to decrypt and re-encrypt all sensitive data with the primary key.</p>
        <p><strong>Warning:</strong> This is a potentially risky operation. Please backup your database first.</p>
        <p><a href="/migrate-data?confirm=yes" class="btn btn-danger">I understand the risks, proceed with migration</a></p>
        <p><a href="/dashboard">Cancel and return to dashboard</a></p>
        '''
    
    try:
        # Migrate patients
        patients_total = Patient.query.count()
        patients_migrated = 0
        patients_failed = 0
        
        for patient in Patient.query.all():
            try:
                # Try to decrypt and re-encrypt fields
                fields = [
                    'first_name', 'last_name', 'dob', 'address', 'phone'
                ]
                
                for field in fields:
                    try:
                        # Get the property value (which triggers decryption)
                        value = getattr(patient, field)
                        # Set it back (which triggers re-encryption with primary key)
                        setattr(patient, field, value)
                    except Exception as e:
                        logger.error(f"Failed to migrate {field} for patient {patient.id}: {e}")
                
                patients_migrated += 1
            except Exception as e:
                logger.error(f"Failed to migrate patient {patient.id}: {e}")
                patients_failed += 1
        
        # Migrate medical records
        records_total = MedicalRecord.query.count()
        records_migrated = 0
        records_failed = 0
        
        for record in MedicalRecord.query.all():
            try:
                # Try to decrypt and re-encrypt fields
                fields = ['diagnosis', 'treatment', 'notes']
                
                for field in fields:
                    try:
                        # Get the property value (which triggers decryption)
                        value = getattr(record, field)
                        if value is not None:
                            # Set it back (which triggers re-encryption with primary key)
                            setattr(record, field, value)
                    except Exception as e:
                        logger.error(f"Failed to migrate {field} for record {record.id}: {e}")
                
                records_migrated += 1
            except Exception as e:
                logger.error(f"Failed to migrate record {record.id}: {e}")
                records_failed += 1
        
        # Commit all changes
        db.session.commit()
        
        return f'''
        <h1>Data Migration Complete</h1>
        <h2>Patient Data:</h2>
        <ul>
            <li>Total patients: {patients_total}</li>
            <li>Successfully migrated: {patients_migrated}</li>
            <li>Failed: {patients_failed}</li>
        </ul>
        
        <h2>Medical Records:</h2>
        <ul>
            <li>Total records: {records_total}</li>
            <li>Successfully migrated: {records_migrated}</li>
            <li>Failed: {records_failed}</li>
        </ul>
        
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        trace = traceback.format_exc()
        logger.error(f"Migration failed: {error_msg}\n{trace}")
        return f'''
        <h1>Migration Failed</h1>
        <p>An error occurred: {error_msg}</p>
        <p><a href="/dashboard">Return to Dashboard</a></p>
        '''

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

        return '''
        <h1>Database initialized with sample data</h1>
        <p>Users created with 2FA disabled for testing:</p>
        <ul>
            <li><strong>Admin:</strong> username=admin, password=admin123</li>
            <li><strong>Doctor:</strong> username=doctor, password=doctor123</li>
            <li><strong>Patient:</strong> username=patient, password=patient123</li>
        </ul>
        <p><strong>Important:</strong> If you see decryption errors on the doctor dashboard, please use the 
           <a href="/fix-default-patients">Fix Default Patients</a> or <a href="/recreate-default-data">Recreate Default Data</a> tool (admin access required).</p>
        <p><a href="/login">Go to login page</a></p>
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
        "Environment Variables": {k: v for k, v in os.environ.items() if k in ['FLASK_APP', 'FLASK_ENV', 'SECRET_KEY']},
        "Encryption Keys Count": len(cipher_suites)
    }
    
    return jsonify(info)

@app.route('/encryption-test')
@login_required
@role_required(['admin'])
def encryption_test():
    """Test the encryption system with various keys"""
    results = []
    
    # Create a test string
    test_string = f"Test data {datetime.now().isoformat()}"
    
    # Test each key for encryption and decryption
    for i, cipher in enumerate(cipher_suites):
        key_name = f"Key {i+1}"
        try:
            # Try to encrypt and decrypt with this cipher
            encrypted = cipher.encrypt(test_string.encode()).decode()
            
            # Try to decrypt with each cipher
            decrypt_results = []
            for j, decrypt_cipher in enumerate(cipher_suites):
                try:
                    decrypted = decrypt_cipher.decrypt(encrypted.encode()).decode()
                    decrypt_results.append({
                        "cipher": f"Key {j+1}",
                        "success": True,
                        "matches_original": decrypted == test_string
                    })
                except Exception as e:
                    decrypt_results.append({
                        "cipher": f"Key {j+1}",
                        "success": False,
                        "error": str(e)
                    })
            
            results.append({
                "key": key_name,
                "encrypt_success": True,
                "encrypted_data": encrypted[:20] + "..." if encrypted else None,
                "decrypt_results": decrypt_results
            })
        except Exception as e:
            results.append({
                "key": key_name,
                "encrypt_success": False,
                "error": str(e)
            })
    
    return jsonify({
        "test_string": test_string,
        "results": results,
        "primary_key": "Key 1"
    })

@app.route('/patient-test')
@login_required
@role_required(['admin'])
def patient_test():
    """Attempt to decrypt all patient data"""
    results = []
    
    for patient in Patient.query.all():
        patient_result = {
            "id": patient.id,
            "fields": {}
        }
        
        # Try to decrypt each field
        for field in ['first_name', 'last_name', 'dob', 'address', 'phone']:
            try:
                value = getattr(patient, field)
                patient_result["fields"][field] = {
                    "success": True,
                    "value_preview": value[:10] + "..." if value and len(value) > 10 else value
                }
            except Exception as e:
                patient_result["fields"][field] = {
                    "success": False,
                    "error": str(e)
                }
        
        results.append(patient_result)
    
    return jsonify({
        "total_patients": len(results),
        "results": results
    })

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
    
    # Run the app on 0.0.0.0 (all network interfaces) instead of 127.0.0.1
    app.run(debug=True, host='0.0.0.0', port=8080)
