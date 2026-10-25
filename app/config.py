import os

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'trustvault-super-secure-production-key-2026')
    
    # Handle Render / Supabase / Neon PostgreSQL URL format
    raw_db_url = os.environ.get('DATABASE_URL')
    if raw_db_url and raw_db_url.startswith("postgres://"):
        raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

    # Handle Vercel serverless read-only filesystem
    if os.environ.get('VERCEL') == '1':
        SQLALCHEMY_DATABASE_URI = raw_db_url or 'sqlite:////tmp/trustvault.db'
        UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
    else:
        SQLALCHEMY_DATABASE_URI = raw_db_url or f"sqlite:///{os.path.join(BASE_DIR, 'trustvault.db')}"
        UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Security headers
    WTF_CSRF_ENABLED = True

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'test_uploads')
