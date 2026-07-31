import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

# Load root .env first, then allow backend-specific .env to override
load_dotenv(os.path.join(ROOT_DIR, '.env'))
load_dotenv(os.path.join(BASE_DIR, '.env'), override=True)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-ids-secret-handshake-token')
    
    # Check if running in Vercel serverless environment
    IS_VERCEL = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None
    
    if IS_VERCEL:
        DATABASE_PATH = '/tmp/database.db'
        UPLOAD_FOLDER = '/tmp/uploads'
        REPORTS_FOLDER = '/tmp/reports'
    else:
        DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'database.db')
        UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
        REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    
    # Directories
    MODEL_FOLDER = os.path.join(BASE_DIR, 'models')
    DATASET_FOLDER = os.path.join(BASE_DIR, 'dataset')
    
    # JWT Authentication Security
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'cyber-ids-jwt-secret-token')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    
    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    ALIENVAULT_OTX_API_KEY = os.environ.get('ALIENVAULT_OTX_API_KEY', '')
    
    # Ingestion constraints
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB upload limit
    ALLOWED_EXTENSIONS = {'csv'}
    
    # Model defaults
    DEFAULT_THRESHOLD = 0.50
    
    @staticmethod
    def init_app(app):
        # Create directories if they don't exist
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
        os.makedirs(Config.MODEL_FOLDER, exist_ok=True)
        os.makedirs(Config.DATASET_FOLDER, exist_ok=True)
        os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
        
        # On Vercel serverless, copy the pre-seeded SQLite database to /tmp
        if Config.IS_VERCEL and not os.path.exists(Config.DATABASE_PATH):
            import shutil
            src_db = os.path.join(BASE_DIR, 'database', 'database.db')
            if os.path.exists(src_db):
                try:
                    shutil.copy2(src_db, Config.DATABASE_PATH)
                except Exception:
                    pass
