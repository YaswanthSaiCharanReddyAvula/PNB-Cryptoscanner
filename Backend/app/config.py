"""
QuantumShield — Application Configuration

Loads settings from environment variables or a .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Central configuration for QuantumShield backend."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "QuantumShield"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── MongoDB (existing scanner pipeline) ──────────────────────
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "quantumshield"

    # ── PostgreSQL (Assessment System API) ───────────────────────
    POSTGRES_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/quantumshield"

    # ── JWT Auth ─────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_A_LONG_RANDOM_SECRET"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # ── CORS (comma-separated origins for the React frontend) ───
    CORS_ORIGINS: List[str] = [
        "*"
    ]

    # ── Scanner defaults ─────────────────────────────────────────
    SCAN_TIMEOUT: int = 36000          # seconds per host (10 hours)
    TOOL_TIMEOUT: int = 300            # max seconds per individual binary (5 mins)
    DEFAULT_PORTS: str = "443,8443,8080,4443"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()
