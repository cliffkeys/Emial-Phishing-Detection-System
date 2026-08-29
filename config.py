import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _get_int_env(var_name: str, default: int) -> int:
    val = os.getenv(var_name)
    if val and val.strip().isdigit():
        return int(val.strip())
    return default


class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY") or "mailshield-default-dev-secret-key-academic-2026"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = _get_int_env("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)  # 16 MB max body
    
    # Model and artifact paths
    MODELS_DIR = BASE_DIR / "models"
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / "reports" / "generated"
    
    # Security headers & cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE") or "Lax"
    SESSION_COOKIE_SECURE = (os.getenv("SESSION_COOKIE_SECURE") or "False").lower() in ("true", "1", "t")

    # Optional Threat Intelligence keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or ""
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or ""
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") or ""


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'mailshield_dev.db'}"
    )


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    # Use postgres or sqlite depending on DATABASE_URL
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        # Fix for SQLAlchemy requiring postgresql:// instead of postgres://
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    # Handle Vercel serverless /tmp environment
    if not database_url:
        if os.getenv("VERCEL"):
            SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/mailshield.db"
        else:
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'instance' / 'mailshield.db'}"
    else:
        SQLALCHEMY_DATABASE_URI = database_url


class TestingConfig(Config):
    """Testing configuration with in-memory database."""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MODELS_DIR = BASE_DIR / "models"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
