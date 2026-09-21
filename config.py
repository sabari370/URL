"""
config.py — PhishGuard AI Application Configuration
=====================================================
Loads environment variables via python-dotenv and exposes typed
configuration classes for Flask's app.config.from_object() pattern.

Usage:
    from config import config
    app.config.from_object(config['development'])
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env file from the project root (one directory above this file, or
# the same directory — whichever exists).
# ---------------------------------------------------------------------------
load_dotenv()


class Config:
    """
    Base configuration shared by all environments.

    All sensitive values are read from environment variables so that secrets
    never live in source code.  Sensible (non-secret) defaults are provided
    where possible.
    """

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-this-in-production")

    # ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------
    MONGO_URI: str = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB_NAME: str = "phishguard"

    # ------------------------------------------------------------------
    # ML model artefact paths (relative to the project root)
    # ------------------------------------------------------------------
    MODEL_PATH: str = os.environ.get("MODEL_PATH", "models/phishing_model.pkl")
    SCALER_PATH: str = os.environ.get("SCALER_PATH", "models/feature_scaler.pkl")
    MODEL_METADATA_PATH: str = os.environ.get(
        "MODEL_METADATA_PATH", "models/model_metadata.json"
    )

    # ------------------------------------------------------------------
    # Flask environment
    # ------------------------------------------------------------------
    FLASK_ENV: str = os.environ.get("FLASK_ENV", "production")

    # ------------------------------------------------------------------
    # Session / cookie security
    # ------------------------------------------------------------------
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=24)

    # ------------------------------------------------------------------
    # File upload limits (used for QR-code image scanning)
    # ------------------------------------------------------------------
    #: Hard cap on request body size — 16 MB.
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024
    #: Permitted image extensions for QR uploads.
    ALLOWED_EXTENSIONS: set = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}

    # ------------------------------------------------------------------
    # Risk classification thresholds
    # Score range 0-100:
    #   0  – 29  → Low         (Likely Safe)
    #   30 – 59  → Suspicious
    #   60 – 100 → High        (Likely Phishing)
    # ------------------------------------------------------------------
    RISK_THRESHOLDS: dict = {"low": 30, "suspicious": 60}
    CLASSIFICATIONS: dict = {
        "low": "Likely Safe",
        "suspicious": "Suspicious",
        "high": "Likely Phishing",
    }

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_FILE: str = "logs/phishguard.log"

    # ------------------------------------------------------------------
    # Password hashing
    # ------------------------------------------------------------------
    #: bcrypt work-factor — 12 is the OWASP-recommended minimum for 2024.
    BCRYPT_LOG_ROUNDS: int = 12

    # ------------------------------------------------------------------
    # Rate limiting (flask-limiter string format)
    # ------------------------------------------------------------------
    RATE_LIMIT: str = "60 per minute"

    # ------------------------------------------------------------------
    # Subclass hooks (overridden per environment)
    # ------------------------------------------------------------------
    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = True
    LOG_LEVEL: str = "INFO"


class DevelopmentConfig(Config):
    """
    Configuration for local development.

    * Debug mode is **on** so Flask reloads on file changes and shows the
      interactive debugger.
    * Secure cookies are **off** because local dev typically runs over plain
      HTTP (no TLS).
    * Log level is set to DEBUG for verbose output.
    """

    DEBUG: bool = True
    SESSION_COOKIE_SECURE: bool = False
    LOG_LEVEL: str = "DEBUG"


class ProductionConfig(Config):
    """
    Configuration for production deployments.

    * Debug mode is **off** — never expose tracebacks to end-users.
    * Secure cookies are **on** — requires HTTPS.
    * Log level is INFO to reduce log volume without hiding errors.

    Ensure the following environment variables are set before deploying:
        SECRET_KEY, MONGO_URI
    """

    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = True
    LOG_LEVEL: str = "INFO"


# ---------------------------------------------------------------------------
# Public registry — pass the value of FLASK_ENV (or another key) to select
# the appropriate config class at application startup.
# ---------------------------------------------------------------------------
config: dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
