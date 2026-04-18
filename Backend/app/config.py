"""
QuantumShield — Application Configuration

Loads settings from environment variables or a .env file.
"""

import re

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


def normalize_llm_chat_url(url: str) -> str:
    """
    LM Studio accepts either a full OpenAI-style URL or a base like http://host:1234.
    Always resolve to .../v1/chat/completions.
    """
    u = (url or "").strip().rstrip("/")
    if not u:
        return "http://127.0.0.1:1234/v1/chat/completions"
    if "chat/completions" in u:
        return u
    if u.endswith("/v1"):
        return f"{u}/chat/completions"
    return f"{u}/v1/chat/completions"


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

    # ── Quantum scoring rollup (see quantum_risk_engine.calculate_score) ──
    # estate_weakest | per_host_min | p25
    QUANTUM_SCORE_AGGREGATION: str = "estate_weakest"

    # ── Scanner defaults ─────────────────────────────────────────
    SCAN_TIMEOUT: int = 600            # seconds per full scan
    TOOL_TIMEOUT: int = 30             # max seconds per individual tool binary
    # testssl.sh is heavy; cap per target (parallel scans × many ports add up). Partial JSON on kill is ignored.
    TESTSSL_TIMEOUT: int = 90
    DEFAULT_PORTS: str = "21,22,443,465,587,990,993,995,1433,3306,3389,5432,6379,8080,8443,27017"
    MAX_SUBDOMAINS: int = 50           # cap subdomains for fast demo scanning

    # ── Phase 2: portfolio / batch scans ─────────────────────────
    MAX_BATCH_DOMAINS: int = 25        # POST /scan/batch list size cap
    MAX_CONCURRENT_SCANS: int = 3      # global scan pipeline concurrency

    # ── Scan retention & in-place rescan (same domain reuses Mongo row + scan_id) ──
    SCAN_RETENTION_DAYS: int = 30  # purge terminal scans older than this (by completed_at)
    SCAN_REUSE_WINDOW_DAYS: int = 30  # rescan within window updates same document + scan_id
    SCAN_PURGE_INTERVAL_SECONDS: int = 3600  # background purge frequency

    # ── Asset classification (HTTP probes; capped per scan) ─────────
    CLASSIFICATION_PROBE_TIMEOUT: float = 8.0
    CLASSIFICATION_MAX_HTTP_PROBES: int = 40

    # ── Optional Nuclei active scan (Linux/server; off on typical Windows dev) ──
    ENABLE_NUCLEI: bool = False
    NUCLEI_BINARY: str = "nuclei"
    NUCLEI_MAX_HOSTS: int = 15
    NUCLEI_TAGS: str = "tls,misconfig,technologies"
    NUCLEI_TEMPLATE_TIMEOUT_SECONDS: int = 10

    # ── LM Studio / OpenAI-compatible LLM (local) ───────────────────
    # Example: http://192.168.56.1:1234/v1/chat/completions
    LLM_BASE_URL: str = "http://127.0.0.1:1234/v1/chat/completions"
    LLM_MODEL: str = "local-model"
    LLM_TIMEOUT_SECONDS: float = 120.0
    LLM_API_KEY: str = ""
    # If True, httpx uses HTTP_PROXY/HTTPS_PROXY from the environment (can break local LM Studio).
    # Keep False unless your LLM is only reachable via a proxy.
    LLM_TRUST_ENV: bool = False

    @computed_field
    @property
    def llm_chat_completions_url(self) -> str:
        return normalize_llm_chat_url(self.LLM_BASE_URL)

    # ── SMTP (scheduled report email) ─────────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_USE_TLS: bool = True

    # ── Scheduled reports ─────────────────────────────────────────
    REPORT_SCHEDULER_POLL_SECONDS: int = 30
    REPORT_MAX_ATTACHMENT_MB: int = 10
    GENERATED_REPORTS_DIR: str = "generated_reports"

    # ── Custom Scanner Engine ─────────────────────────────────────
    SCANNER_PORT_PROFILE: str = "standard"
    SCANNER_MAX_SUBDOMAINS: int = 200
    SCANNER_DNS_TIMEOUT: float = 3.0
    SCANNER_TCP_TIMEOUT: float = 2.0
    SCANNER_BANNER_TIMEOUT: float = 3.0
    SCANNER_TLS_TIMEOUT: float = 5.0
    SCANNER_HTTP_TIMEOUT: float = 10.0
    SCANNER_MAX_CIPHER_PROBES: int = 30
    SCANNER_ENABLE_CT_LOGS: bool = True
    SCANNER_ENABLE_WHOIS: bool = True
    SCANNER_ENABLE_ASN_LOOKUP: bool = True
    SCANNER_ENABLE_ZONE_TRANSFER: bool = True
    SCANNER_ENABLE_BRUTE_FORCE: bool = True
    SCANNER_SCAN_DEPTH: str = "standard"
    SCANNER_MAX_SCAN_SECONDS: int = 900
    SCANNER_MAX_TOTAL_REQUESTS: int = 10000
    SCANNER_GLOBAL_CONCURRENCY: int = 500
    SCANNER_RESPECT_ROBOTS: bool = True
    SCANNER_AI_ADAPTIVE: bool = True
    SCANNER_STAGE_VERBOSE_LOGS: bool = True
    SCANNER_STAGE_WS_SUMMARY: bool = True
    SCANNER_STAGE_DB_SUMMARY: bool = True
    SCANNER_STAGE_PREVIEW_LIMIT: int = 3
    SCANNER_STAGE_MESSAGE_MAX_LEN: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
