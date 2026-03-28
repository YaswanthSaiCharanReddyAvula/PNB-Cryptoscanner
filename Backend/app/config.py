"""
QuantumShield — Application Configuration

Loads settings from environment variables or a .env file.
"""

import re

from pydantic import Field, computed_field, field_validator
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

    # ── CORS: use "*" for all origins, or comma-separated URLs (no JSON list).
    # With "*", Starlette sets allow_credentials=False (required by browsers).
    CORS_ORIGINS: str = Field(default="*")

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def normalize_cors_origins(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            return "*"
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1].strip()
        if not s:
            return "*"
        # Legacy copies: JSON list string or quoted wildcard
        if re.fullmatch(r'\[\s*["\']?\*["\']?\s*\]', s):
            return "*"
        if s in ("*", '"*"', "'*'"):
            return "*"
        return s

    @computed_field
    @property
    def cors_origins_list(self) -> List[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [x.strip() for x in self.CORS_ORIGINS.split(",") if x.strip()]

    @computed_field
    @property
    def cors_allow_credentials(self) -> bool:
        """False when using wildcard origin (browser + Starlette rules)."""
        return self.CORS_ORIGINS.strip() != "*"

    # ── Scanner defaults ─────────────────────────────────────────
    SCAN_TIMEOUT: int = 120            # seconds per full scan
    TOOL_TIMEOUT: int = 30             # max seconds per individual tool binary
    # testssl.sh is heavy; cap per target (parallel scans × many ports add up). Partial JSON on kill is ignored.
    TESTSSL_TIMEOUT: int = 90
    DEFAULT_PORTS: str = "21,22,443,465,587,990,993,995,1433,3306,3389,5432,6379,8080,8443,27017"
    MAX_SUBDOMAINS: int = 50           # cap subdomains for fast demo scanning

    # ── Phase 2: portfolio / batch scans ─────────────────────────
    MAX_BATCH_DOMAINS: int = 25        # POST /scan/batch list size cap
    MAX_CONCURRENT_SCANS: int = 3      # global scan pipeline concurrency

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()
