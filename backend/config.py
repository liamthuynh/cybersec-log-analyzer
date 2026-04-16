"""
Application Configuration

Centralizes all environment-based settings so the rest of the app
imports from here instead of calling os.environ directly.
Usage:
    from config import Config
    app.config.from_object(Config)
"""

import os


class Config:
    # ------------------------------------------------------------------ #
    # Security
    # ------------------------------------------------------------------ #
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

    # ------------------------------------------------------------------ #
    # File Uploads
    # ------------------------------------------------------------------ #
    UPLOAD_FOLDER: str = os.path.join(os.path.dirname(__file__), "uploads")
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS: set = {"txt", "log", "csv"}

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL",
        "postgresql://cyberscope:cyberscope@localhost:5432/cyberscope",
    )

    # ------------------------------------------------------------------ #
    # AI / Anthropic
    # ------------------------------------------------------------------ #
    ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")
    AI_MODEL: str = os.environ.get("AI_MODEL", "claude-sonnet-4-6")
    AI_MAX_TOKENS: int = int(os.environ.get("AI_MAX_TOKENS", "2000"))
    AI_MAX_SAMPLE_ENTRIES: int = int(os.environ.get("AI_MAX_SAMPLE_ENTRIES", "50"))

    # ------------------------------------------------------------------ #
    # Server
    # ------------------------------------------------------------------ #
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "8000"))
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "0") == "1"

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    # In production, restrict to your frontend origin, e.g. "https://yourapp.com"
    CORS_ORIGINS: str = os.environ.get("CORS_ORIGINS", "*")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    # Enforce a real secret key in production
    SECRET_KEY: str = os.environ["SECRET_KEY"]  # will raise if unset


# Map name → class for easy selection
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}

ActiveConfig = config_map.get(os.environ.get("FLASK_ENV", "default"), DevelopmentConfig)
