"""
Configuration file for Root CA Certificate Management System
Modify these settings according to your environment
"""

import os

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    # Root CA Configuration
    ROOT_CA_CERT_PATH = '/etc/mycerts/rootCA.crt'
    ROOT_CA_KEY_PATH = '/etc/mycerts/rootCA.key'
    
    # File Upload Configuration
    UPLOAD_FOLDER = '/tmp/csr_uploads'
    PROCESSING_FOLDER = '/tmp/cert_processing'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Certificate Configuration
    CERTIFICATE_VALIDITY_DAYS = 365
    CERTIFICATE_ALGORITHM = 'sha256'
    
    # Logging Configuration
    LOG_FILE = '/var/log/rootca/app.log'
    LOG_LEVEL = 'INFO'
    
    # Server Configuration
    HOST = '0.0.0.0'
    PORT = 5000
    DEBUG = False
    
    # Security Configuration
    ALLOWED_EXTENSIONS = {'csr', 'pem'}
    
    # Cleanup Configuration
    AUTO_CLEANUP_AFTER_HOURS = 24  # Auto cleanup files after 24 hours
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration."""
        pass

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    
    # Production security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    UPLOAD_FOLDER = '/tmp/test_csr_uploads'
    PROCESSING_FOLDER = '/tmp/test_cert_processing'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': Config
}

