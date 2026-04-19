import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
    FILE_PATH_PEPPER = "PEPPERsecure284920370472375"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt'}
    ALLOWED_MIME_TYPES = {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain"
    }
    SESSION_TIMEOUT = 1800  # 30 minutes
    BCRYPT_ROUNDS = 12
    RATE_LIMIT_MAX = 10
    RATE_LIMIT_WINDOW = 60  # seconds
    LOCKOUT_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes