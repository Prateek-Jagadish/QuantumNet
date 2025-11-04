"""
QuantumNet Configuration Module

This module contains configuration settings for the QuantumNet application.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration class."""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DEBUG = False
    TESTING = False
    
    # Database Configuration
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or 'data/quantumnet.db'
    
    # Quantum Key Configuration
    DEFAULT_KEY_BITS = int(os.environ.get('DEFAULT_KEY_BITS', '1000'))
    DEFAULT_KEY_EXPIRY_HOURS = int(os.environ.get('DEFAULT_KEY_EXPIRY_HOURS', '24'))
    MAX_KEY_BITS = int(os.environ.get('MAX_KEY_BITS', '10000'))
    
    # Encryption Configuration
    AES_KEY_SIZE = 32  # 256 bits
    AES_BLOCK_SIZE = 16  # 128 bits
    
    # ML Model Configuration
    ML_MODEL_PATH = os.environ.get('ML_MODEL_PATH') or 'models/security_classifier.pkl'
    ML_TRAINING_SAMPLES_PER_CLASS = int(os.environ.get('ML_TRAINING_SAMPLES_PER_CLASS', '1000'))
    ML_VALIDATION_SAMPLES_PER_CLASS = int(os.environ.get('ML_VALIDATION_SAMPLES_PER_CLASS', '200'))
    
    # Security Configuration
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=int(os.environ.get('LOGIN_LOCKOUT_MINUTES', '15')))
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get('SESSION_LIFETIME_HOURS', '24')))
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', '16')) * 1024 * 1024  # 16MB
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE') or 'logs/quantumnet.log'
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.environ.get('RATE_LIMIT_REQUESTS_PER_MINUTE', '60'))
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
    
    # Quantum Protocol Configuration
    QUANTUM_PROTOCOL_DEFAULT_BITS = int(os.environ.get('QUANTUM_PROTOCOL_DEFAULT_BITS', '1000'))
    QUANTUM_PROTOCOL_MAX_BITS = int(os.environ.get('QUANTUM_PROTOCOL_MAX_BITS', '10000'))
    QUANTUM_PROTOCOL_MIN_BITS = int(os.environ.get('QUANTUM_PROTOCOL_MIN_BITS', '100'))
    
    # Channel Configuration
    DEFAULT_NOISE_LEVEL = float(os.environ.get('DEFAULT_NOISE_LEVEL', '0.0'))
    DEFAULT_SUCCESS_RATE = float(os.environ.get('DEFAULT_SUCCESS_RATE', '1.0'))
    
    # Security Monitoring
    SECURITY_MONITORING_ENABLED = os.environ.get('SECURITY_MONITORING_ENABLED', 'true').lower() == 'true'
    SECURITY_EVENT_RETENTION_DAYS = int(os.environ.get('SECURITY_EVENT_RETENTION_DAYS', '30'))
    
    # Performance Configuration
    ENABLE_CACHING = os.environ.get('ENABLE_CACHING', 'true').lower() == 'true'
    CACHE_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT', '300'))  # 5 minutes
    
    # Backup Configuration
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', 'true').lower() == 'true'
    BACKUP_INTERVAL_HOURS = int(os.environ.get('BACKUP_INTERVAL_HOURS', '24'))
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', '7'))


class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    TESTING = False
    
    # Development-specific settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    ML_TRAINING_SAMPLES_PER_CLASS = 100  # Smaller dataset for development
    ML_VALIDATION_SAMPLES_PER_CLASS = 20
    
    # More verbose logging
    LOG_LEVEL = 'DEBUG'
    
    # Relaxed security for development
    MAX_LOGIN_ATTEMPTS = 10
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=5)
    
    # Enable hot reloading
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(Config):
    """Production configuration."""
    
    DEBUG = False
    TESTING = False
    
    # Production-specific settings
    ML_TRAINING_SAMPLES_PER_CLASS = 5000  # Larger dataset for production
    ML_VALIDATION_SAMPLES_PER_CLASS = 1000
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Strict security for production
    MAX_LOGIN_ATTEMPTS = 3
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=30)
    
    # Performance optimizations
    ENABLE_CACHING = True
    CACHE_TIMEOUT = 600  # 10 minutes
    
    # Security enhancements
    SECURITY_MONITORING_ENABLED = True
    RATE_LIMIT_ENABLED = True


class TestingConfig(Config):
    """Testing configuration."""
    
    DEBUG = False
    TESTING = True
    
    # Test-specific settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'test-secret-key')
    DATABASE_PATH = ':memory:'  # Use in-memory database for tests
    ML_MODEL_PATH = 'test_models/test_classifier.pkl'
    
    # Minimal training data for tests
    ML_TRAINING_SAMPLES_PER_CLASS = 10
    ML_VALIDATION_SAMPLES_PER_CLASS = 5
    
    # Disable external services
    SECURITY_MONITORING_ENABLED = False
    RATE_LIMIT_ENABLED = False
    BACKUP_ENABLED = False
    
    # Fast execution
    QUANTUM_PROTOCOL_DEFAULT_BITS = 100
    DEFAULT_KEY_EXPIRY_HOURS = 1


class DockerConfig(Config):
    """Docker-specific configuration."""
    
    DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    # Docker-specific paths
    DATABASE_PATH = '/app/data/quantumnet.db'
    ML_MODEL_PATH = '/app/models/security_classifier.pkl'
    LOG_FILE = '/app/logs/quantumnet.log'
    
    # Docker networking
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', '5000'))
    
    # Container-specific settings
    WORKERS = int(os.environ.get('WORKERS', '4'))
    TIMEOUT = int(os.environ.get('TIMEOUT', '30'))


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """
    Get configuration class based on environment.
    
    Args:
        config_name: Configuration name (optional)
        
    Returns:
        Configuration class
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    return config.get(config_name, config['default'])


# Environment-specific settings
def get_database_url():
    """Get database URL based on environment."""
    if os.environ.get('DATABASE_URL'):
        return os.environ.get('DATABASE_URL')
    
    db_path = Config.DATABASE_PATH
    if db_path == ':memory:':
        return 'sqlite:///:memory:'
    else:
        return f'sqlite:///{db_path}'


def get_redis_url():
    """Get Redis URL for caching and sessions."""
    return os.environ.get('REDIS_URL', 'redis://localhost:6379/0')


def get_mail_config():
    """Get email configuration."""
    return {
        'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'localhost'),
        'MAIL_PORT': int(os.environ.get('MAIL_PORT', '587')),
        'MAIL_USE_TLS': os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
        'MAIL_USERNAME': os.environ.get('MAIL_USERNAME'),
        'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD'),
        'MAIL_DEFAULT_SENDER': os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@quantumnet.com')
    }


def get_monitoring_config():
    """Get monitoring configuration."""
    return {
        'ENABLE_METRICS': os.environ.get('ENABLE_METRICS', 'true').lower() == 'true',
        'METRICS_PORT': int(os.environ.get('METRICS_PORT', '9090')),
        'HEALTH_CHECK_ENDPOINT': os.environ.get('HEALTH_CHECK_ENDPOINT', '/health'),
        'READINESS_CHECK_ENDPOINT': os.environ.get('READINESS_CHECK_ENDPOINT', '/ready')
    }


def get_security_config():
    """Get security configuration."""
    return {
        'ENABLE_2FA': os.environ.get('ENABLE_2FA', 'false').lower() == 'true',
        'SESSION_COOKIE_SECURE': os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true',
        'SESSION_COOKIE_HTTPONLY': os.environ.get('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true',
        'SESSION_COOKIE_SAMESITE': os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
        'PASSWORD_MIN_LENGTH': int(os.environ.get('PASSWORD_MIN_LENGTH', '8')),
        'PASSWORD_REQUIRE_SPECIAL': os.environ.get('PASSWORD_REQUIRE_SPECIAL', 'true').lower() == 'true'
    }


def validate_config():
    """Validate configuration settings."""
    errors = []
    
    # Validate numeric values
    if Config.DEFAULT_KEY_BITS < Config.QUANTUM_PROTOCOL_MIN_BITS:
        errors.append(f"DEFAULT_KEY_BITS ({Config.DEFAULT_KEY_BITS}) must be >= QUANTUM_PROTOCOL_MIN_BITS ({Config.QUANTUM_PROTOCOL_MIN_BITS})")
    
    if Config.DEFAULT_KEY_BITS > Config.QUANTUM_PROTOCOL_MAX_BITS:
        errors.append(f"DEFAULT_KEY_BITS ({Config.DEFAULT_KEY_BITS}) must be <= QUANTUM_PROTOCOL_MAX_BITS ({Config.QUANTUM_PROTOCOL_MAX_BITS})")
    
    if Config.DEFAULT_SUCCESS_RATE < 0 or Config.DEFAULT_SUCCESS_RATE > 1:
        errors.append(f"DEFAULT_SUCCESS_RATE ({Config.DEFAULT_SUCCESS_RATE}) must be between 0 and 1")
    
    if Config.DEFAULT_NOISE_LEVEL < 0 or Config.DEFAULT_NOISE_LEVEL > 1:
        errors.append(f"DEFAULT_NOISE_LEVEL ({Config.DEFAULT_NOISE_LEVEL}) must be between 0 and 1")
    
    # Validate paths
    if not os.path.exists(os.path.dirname(Config.DATABASE_PATH)):
        try:
            os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create database directory: {e}")
    
    if not os.path.exists(os.path.dirname(Config.ML_MODEL_PATH)):
        try:
            os.makedirs(os.path.dirname(Config.ML_MODEL_PATH), exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create model directory: {e}")
    
    if errors:
        raise ValueError(f"Configuration validation failed:\n" + "\n".join(errors))
    
    return True


# Initialize configuration validation
if __name__ == "__main__":
    try:
        validate_config()
        print("Configuration validation passed!")
    except ValueError as e:
        print(f"Configuration validation failed: {e}")
        exit(1)
