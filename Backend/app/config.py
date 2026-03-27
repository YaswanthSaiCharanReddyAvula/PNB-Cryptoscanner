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

    # ── JWT Auth ─────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_A_LONG_RANDOM_SECRET"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # ── CORS (comma-separated origins for the React frontend) ───
    CORS_ORIGINS: List[str] = [
        "*"
    ]

    # ── Scanner defaults ─────────────────────────────────────────
    SCAN_TIMEOUT: int = 120            # seconds per full scan
    TOOL_TIMEOUT: int = 30             # max seconds per individual tool binary
    DEFAULT_PORTS: str = "21,22,443,465,587,990,993,995,1433,3306,3389,5432,6379,8080,8443,27017"
    MAX_SUBDOMAINS: int = 50           # cap subdomains for fast demo scanning

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()
