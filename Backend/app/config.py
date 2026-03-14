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

    # ── MongoDB ──────────────────────────────────────────────────
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "quantumshield"

    # ── CORS (comma-separated origins for the React frontend) ───
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://192.168.128.206:5173",
        "http://172.30.87.37:5173",
        "http://172.30.86.107:5173",
        "http://172.30.86.107:3000",
        "http://172.30.86.115:5173",
        "http://172.30.86.115:3000",
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
