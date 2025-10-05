#!/usr/bin/env python3
"""
Root CA Certificate Management Web Application

This application allows users to:
1. Login with authentication
2. Upload CSR files
3. Enter FQHN (Fully Qualified Host Name)
4. Generate SSL certificates signed by the root CA
5. Download archives containing the certificate and root CA cert
6. Clean up temporary files

The application handles concurrent access using file locking mechanisms.
"""

import os
import sys
import subprocess
import tempfile
import threading
import time
import uuid
import shutil
import zipfile
import fcntl
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify, session, abort
from markupsafe import Markup
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, FileField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
import logging
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/rootca/app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production-very-long-random-string'

# Enable CSRF protection
csrf = CSRFProtect(app)

# Configuration
ROOT_CA_CERT_PATH = '/etc/mycerts/rootCA.crt'
ROOT_CA_KEY_PATH = '/etc/mycerts/rootCA.key'
ROOT_CA_KEY_PASSWORD = 'P@ssw0rd'
UPLOAD_FOLDER = '/tmp/csr_uploads'
PROCESSING_FOLDER = '/tmp/cert_processing'
ALLOWED_EXTENSIONS = {'csr', 'pem'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
SESSION_TIMEOUT = 3600  # 1 hour session timeout

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSING_FOLDER'] = PROCESSING_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Global lock for file operations
file_lock = threading.Lock()

# User management (in production, use a proper database)
USERS = {
    'admin': {
        'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin',
        'last_login': None
    },
    'operator': {
        'password_hash': hashlib.sha256('operator123'.encode()).hexdigest(),
        'role': 'operator',
        'last_login': None
    }
}

# Ensure directories exist
for folder in [UPLOAD_FOLDER, PROCESSING_FOLDER]:
    os.makedirs(folder, exist_ok=True)
    os.chmod(folder, 0o755)

class LoginForm(FlaskForm):
    """Login form with validation."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CertificateRequestForm(FlaskForm):
    """Certificate request form with validation."""
    fqhn = StringField('Fully Qualified Host Name', 
                      validators=[DataRequired(), Length(min=5, max=253)],
                      render_kw={'placeholder': 'e.g., cahttp.egypt.aast.edu'})
    csr_file = FileField('CSR File', validators=[DataRequired()])
    submit = SubmitField('Generate Certificate')

    def validate_fqhn(self, field):
        """Validate FQHN format."""
        fqhn = field.data.strip()
        if not fqhn:
            raise ValidationError('FQHN cannot be empty')
        
        # Basic FQHN validation
        if len(fqhn.split('.')) < 3:
            raise ValidationError('FQHN must have at least 3 parts (e.g., host.domain.com)')
        
        # Check for invalid characters
        import re
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', fqhn):
            raise ValidationError('Invalid FQHN format')

    def validate_csr_file(self, field):
        """Validate CSR file."""
        if field.data:
            filename = field.data.filename
            if not allowed_file(filename):
                raise ValidationError('Invalid file type. Please upload a .csr or .pem file.')
            
            # Reset file pointer for later use
            field.data.seek(0)

def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not login_required(f):
            return redirect(url_for('login'))
        
        user_id = session.get('user_id')
        if user_id not in USERS or USERS[user_id]['role'] != 'admin':
            abort(403)
        
        return f(*args, **kwargs)
    
    return decorated_function

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_domain_from_fqhn(fqhn):
    """
    Extract domain name from FQHN.
    For example: cahttp.egypt.aast.edu -> egypt.aast.edu
    """
    try:
        parts = fqhn.split('.')
        if len(parts) < 3:
            raise ValueError("FQHN must have at least 3 parts (e.g., host.domain.tld)")
        
        # Remove the first part (hostname) to get domain
        domain = '.'.join(parts[1:])
        return domain
    except Exception as e:
        logger.error(f"Error extracting domain from FQHN {fqhn}: {e}")
        raise ValueError(f"Invalid FQHN format: {e}")

def generate_extension_file(fqhn, output_path):
    """Generate extension file with subjectAltName."""
    try:
        domain = extract_domain_from_fqhn(fqhn)
        san_content = f"subjectAltName=DNS:{domain},DNS:{fqhn}"
        
        with open(output_path, 'w') as f:
            f.write(san_content)
        
        logger.info(f"Generated extension file: {output_path} with SAN: {san_content}")
        return san_content
    except Exception as e:
        logger.error(f"Error generating extension file: {e}")
        raise

def sign_certificate(csr_path, extension_path, output_path, days=365):
    """Sign the certificate using OpenSSL with password-protected private key."""
    try:
        # Create a temporary password file
        password_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        password_file.write(ROOT_CA_KEY_PASSWORD)
        password_file.close()
        
        # Make password file readable only by owner
        os.chmod(password_file.name, 0o600)
        
        cmd = [
            'sudo', 'openssl', 'x509', '-req',
            '-in', csr_path,
            '-CA', ROOT_CA_CERT_PATH,
            '-CAkey', ROOT_CA_KEY_PATH,
            '-passin', f'file:{password_file.name}',
            '-CAcreateserial',
            '-out', output_path,
            '-days', str(days),
            '-sha256',
            '-extfile', extension_path
        ]
        
        logger.info(f"Executing command: {' '.join(cmd[:-1])} -passin file:[PASSWORD_FILE]")
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"Certificate signed successfully: {output_path}")
        
        # Clean up password file
        os.unlink(password_file.name)
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error signing certificate: {e.stderr}")
        # Clean up password file on error
        try:
            os.unlink(password_file.name)
        except:
            pass
        return False
    except Exception as e:
        logger.error(f"Unexpected error signing certificate: {e}")
        # Clean up password file on error
        try:
            os.unlink(password_file.name)
        except:
            pass
        return False

def create_archive(cert_path, root_ca_path, archive_path):
    """Create a zip archive containing the certificate and root CA certificate."""
    try:
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add the signed certificate
            zipf.write(cert_path, 'server.crt')
            # Add the root CA certificate
            zipf.write(root_ca_path, 'rootCA.crt')
        
        logger.info(f"Archive created successfully: {archive_path}")
        return True
    except Exception as e:
        logger.error(f"Error creating archive: {e}")
        return False

def cleanup_files(file_paths):
    """Clean up temporary files."""
    for file_path in file_paths:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Cleaned up file: {file_path}")
        except Exception as e:
            logger.error(f"Error cleaning up file {file_path}: {e}")

def process_certificate_request(fqhn, csr_file_path, session_id, user_id):
    """
    Process a certificate request with proper locking and error handling.
    Returns a tuple: (success, result_path, error_message)
    """
    with file_lock:
        try:
            # Create session-specific directory
            session_dir = os.path.join(PROCESSING_FOLDER, session_id)
            os.makedirs(session_dir, exist_ok=True)
            
            # Define file paths
            extension_file = os.path.join(session_dir, 'san.ext')
            cert_file = os.path.join(session_dir, 'server.crt')
            archive_file = os.path.join(session_dir, 'certificate_archive.zip')
            
            # Step 1: Generate extension file
            logger.info(f"Generating extension file for FQHN: {fqhn} (user: {user_id})")
            generate_extension_file(fqhn, extension_file)
            
            # Step 2: Sign the certificate
            logger.info(f"Signing certificate for session: {session_id} (user: {user_id})")
            if not sign_certificate(csr_file_path, extension_file, cert_file):
                return False, None, "Failed to sign certificate. Check logs for details."
            
            # Step 3: Create archive
            logger.info(f"Creating archive for session: {session_id} (user: {user_id})")
            if not create_archive(cert_file, ROOT_CA_CERT_PATH, archive_file):
                return False, None, "Failed to create archive. Check logs for details."
            
            logger.info(f"Certificate processing completed successfully for session: {session_id} (user: {user_id})")
            return True, archive_file, None
            
        except Exception as e:
            logger.error(f"Error processing certificate request for user {user_id}: {e}")
            return False, None, f"Processing error: {str(e)}"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'GET':
        # If already logged in, redirect to main page
        if 'user_id' in session:
            return redirect(url_for('index'))
        return render_template('login.html', form=LoginForm())
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Verify credentials
        if username in USERS:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if USERS[username]['password_hash'] == password_hash:
                # Login successful
                session['user_id'] = username
                session['last_activity'] = datetime.now().isoformat()
                
                # Update last login
                USERS[username]['last_login'] = datetime.now().isoformat()
                
                logger.info(f"User {username} logged in successfully")
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('index'))
        
        logger.warning(f"Failed login attempt for user: {username}")
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Handle user logout."""
    if 'user_id' in session:
        username = session['user_id']
        logger.info(f"User {username} logged out")
        session.clear()
        flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main page with the certificate request form."""
    user_id = session.get('user_id', 'Unknown')
    user_role = USERS.get(user_id, {}).get('role', 'unknown')
    return render_template('index.html', form=CertificateRequestForm(), user_role=user_role)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload and certificate generation."""
    form = CertificateRequestForm()
    
    if not form.validate_on_submit():
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
        return redirect(url_for('index'))
    
    fqhn = form.fqhn.data.strip()
    csr_file = form.csr_file.data
    
    user_id = session.get('user_id', 'unknown')
    
    try:
        # Generate unique session ID
        session_id = str(uuid.uuid4())
        
        # Save uploaded file
        filename = secure_filename(csr_file.filename)
        csr_path = os.path.join(UPLOAD_FOLDER, f"{session_id}_{filename}")
        csr_file.save(csr_path)
        
        logger.info(f"File uploaded: {filename} for FQHN: {fqhn}, session: {session_id}, user: {user_id}")
        
        # Process the certificate request
        success, result_path, error_msg = process_certificate_request(fqhn, csr_path, session_id, user_id)
        
        if success:
            # Clean up CSR file
            cleanup_files([csr_path])
            
            # Store session info for download
            session_info = {
                'session_id': session_id,
                'fqhn': fqhn,
                'archive_path': result_path,
                'created_at': datetime.now().isoformat(),
                'user_id': user_id
            }
            
            # Store session info in file
            session_file = os.path.join(PROCESSING_FOLDER, f"{session_id}.info")
            with open(session_file, 'w') as f:
                for key, value in session_info.items():
                    f.write(f"{key}={value}\n")
            
            flash(f'Certificate generated successfully for {fqhn}', 'success')
            return redirect(url_for('download', session_id=session_id))
        else:
            # Clean up on failure
            cleanup_files([csr_path])
            flash(f'Error generating certificate: {error_msg}', 'error')
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Error in upload_file for user {user_id}: {e}")
        flash(f'An unexpected error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download/<session_id>')
@login_required
def download(session_id):
    """Handle file download."""
    user_id = session.get('user_id', 'unknown')
    
    try:
        session_file = os.path.join(PROCESSING_FOLDER, f"{session_id}.info")
        
        if not os.path.exists(session_file):
            logger.warning(f"Session not found: {session_id} (user: {user_id})")
            flash('Session not found or expired', 'error')
            return redirect(url_for('index'))
        
        # Read session info
        session_info = {}
        with open(session_file, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    session_info[key] = value
        
        # Check if user has access to this session
        if session_info.get('user_id') != user_id and USERS.get(user_id, {}).get('role') != 'admin':
            logger.warning(f"Unauthorized download attempt: {session_id} by user: {user_id}")
            abort(403)
        
        archive_path = session_info.get('archive_path')
        fqhn = session_info.get('fqhn', 'certificate')
        
        if not archive_path or not os.path.exists(archive_path):
            logger.error(f"Archive file not found: {archive_path}")
            flash('Archive file not found', 'error')
            return redirect(url_for('index'))
        
        logger.info(f"File downloaded: {archive_path} by user: {user_id}")
        
        # Send file for download
        return send_file(
            archive_path,
            as_attachment=True,
            download_name=f"{fqhn}_certificate_archive.zip",
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error(f"Error in download for user {user_id}: {e}")
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/cleanup/<session_id>')
@login_required
def cleanup(session_id):
    """Clean up session files after download."""
    user_id = session.get('user_id', 'unknown')
    
    try:
        session_dir = os.path.join(PROCESSING_FOLDER, session_id)
        session_file = os.path.join(PROCESSING_FOLDER, f"{session_id}.info")
        
        # Check if user has access to this session
        if os.path.exists(session_file):
            with open(session_file, 'r') as f:
                session_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        session_info[key] = value
            
            if session_info.get('user_id') != user_id and USERS.get(user_id, {}).get('role') != 'admin':
                logger.warning(f"Unauthorized cleanup attempt: {session_id} by user: {user_id}")
                abort(403)
        
        files_to_cleanup = []
        
        # Add session directory contents
        if os.path.exists(session_dir):
            for file in os.listdir(session_dir):
                files_to_cleanup.append(os.path.join(session_dir, file))
            files_to_cleanup.append(session_dir)
        
        # Add session info file
        if os.path.exists(session_file):
            files_to_cleanup.append(session_file)
        
        cleanup_files(files_to_cleanup)
        
        logger.info(f"Files cleaned up for session: {session_id} by user: {user_id}")
        flash('Files cleaned up successfully', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in cleanup for user {user_id}: {e}")
        flash(f'Error cleaning up files: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/status')
@login_required
def status():
    """API endpoint to check application status."""
    try:
        # Check if root CA files exist
        ca_exists = os.path.exists(ROOT_CA_CERT_PATH)
        key_exists = os.path.exists(ROOT_CA_KEY_PATH)
        
        return jsonify({
            'status': 'healthy',
            'root_ca_cert_exists': ca_exists,
            'root_ca_key_exists': key_exists,
            'upload_folder_writable': os.access(UPLOAD_FOLDER, os.W_OK),
            'processing_folder_writable': os.access(PROCESSING_FOLDER, os.W_OK),
            'user': session.get('user_id'),
            'role': USERS.get(session.get('user_id', ''), {}).get('role', 'unknown')
        })
    except Exception as e:
        logger.error(f"Error in status check: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/admin')
@admin_required
def admin():
    """Admin panel for user management and system status."""
    users_info = []
    for username, info in USERS.items():
        users_info.append({
            'username': username,
            'role': info['role'],
            'last_login': info['last_login']
        })
    
    return render_template('admin.html', users=users_info)

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404, 
                         error_message='Page not found'), 404

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors."""
    return render_template('error.html', 
                         error_code=403, 
                         error_message='Access denied'), 403

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', 
                         error_code=500, 
                         error_message='Internal server error'), 500

if __name__ == '__main__':
    # Verify root CA files exist
    if not os.path.exists(ROOT_CA_CERT_PATH):
        logger.error(f"Root CA certificate not found: {ROOT_CA_CERT_PATH}")
        sys.exit(1)
    
    if not os.path.exists(ROOT_CA_KEY_PATH):
        logger.error(f"Root CA key not found: {ROOT_CA_KEY_PATH}")
        sys.exit(1)
    
    logger.info("Starting Root CA Certificate Management Application with Authentication")
    app.run(host='0.0.0.0', port=5000, debug=False)