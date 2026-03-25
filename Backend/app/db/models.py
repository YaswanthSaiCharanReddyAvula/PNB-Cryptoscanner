"""
QuantumShield — Pydantic Data Models

Defines the request/response schemas and internal data structures
used across the scanning pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"



class AlgorithmCategory(str, Enum):
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    CIPHER = "cipher"
    HASH = "hash"
    PROTOCOL = "protocol"


class QuantumStatus(str, Enum):
    VULNERABLE = "vulnerable"
    PARTIALLY_SAFE = "partially_safe"
    QUANTUM_SAFE = "quantum_safe"


# ── Sub-models ───────────────────────────────────────────────────

class DiscoveredAsset(BaseModel):
    """A single discovered subdomain / host."""
    subdomain: str
    ip: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)


class CertificateInfo(BaseModel):
    """X.509 certificate metadata."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    days_until_expiry: Optional[int] = None
    is_self_signed: bool = False


class CertChainEntry(BaseModel):
    """One certificate in the chain (leaf → intermediate → root)."""
    depth: int
    subject: Optional[str] = None
    issuer: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    is_valid: bool = True
    error: Optional[str] = None


class TLSInfo(BaseModel):
    """TLS details extracted for a single host:port."""
    host: str
    port: int
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_bits: Optional[int] = None
    key_exchange: Optional[str] = None
    certificate: Optional[CertificateInfo] = None
    # ── Enhanced fields ──
    all_supported_protocols: List[str] = Field(default_factory=list)
    all_supported_ciphers: List[Dict[str, Any]] = Field(default_factory=list)
    supports_forward_secrecy: bool = False
    cert_chain: List[CertChainEntry] = Field(default_factory=list)
    confidence: Optional[ConfidenceLevel] = None
    error: Optional[str] = None


# Forward-ref update
TLSInfo.model_rebuild()


class HeaderFinding(BaseModel):
    """A single HTTP security header finding."""
    header: str
    present: bool
    value: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.SAFE
    recommendation: str = ""


class HeadersResult(BaseModel):
    """HTTP security headers scan result for a host."""
    host: str
    findings: List[HeaderFinding] = Field(default_factory=list)
    score: float = 0  # 0-100 headers security score


class CVEFinding(BaseModel):
    """A known CVE/attack mapped to the scan findings."""
    cve_id: str
    name: str
    severity: RiskLevel
    affected_component: str
    description: str
    mitigation: str


class CryptoComponent(BaseModel):
    """A single cryptographic component in the CBOM."""
    name: str
    category: AlgorithmCategory
    key_size: Optional[int] = None
    usage_context: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    quantum_status: QuantumStatus = QuantumStatus.VULNERABLE
    details: Optional[str] = None


class QuantumScoreBreakdown(BaseModel):
    """Per-category scores that feed into the aggregate."""
    key_exchange_score: float = 0
    signature_score: float = 0
    cipher_score: float = 0
    protocol_score: float = 0


class QuantumScore(BaseModel):
    """Overall Quantum Readiness Score."""
    score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    breakdown: QuantumScoreBreakdown
    summary: str = ""


class Recommendation(BaseModel):
    """A migration recommendation for a single component."""
    current_algorithm: str
    recommended_algorithm: str
    category: AlgorithmCategory
    priority: RiskLevel
    rationale: str
    migration_notes: str = ""


class NameServerInfo(BaseModel):
    """DNS Name Server record metadata."""
    hostname: str
    type: str = "NS"
    ip_address: Optional[str] = None
    ttl: Optional[int] = None


# ── Top-level request / response models ──────────────────────────

class ScanRequest(BaseModel):
    """Incoming scan request from the API."""
    domain: str
    include_subdomains: bool = True
    ports: Optional[str] = None  # comma-separated, e.g. "443,8443"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResult(BaseModel):
    """Full result of a scan stored in MongoDB."""
    scan_id: Optional[str] = None
    domain: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    assets: List[DiscoveredAsset] = Field(default_factory=list)
    tls_results: List[TLSInfo] = Field(default_factory=list)
    cbom: List[CryptoComponent] = Field(default_factory=list)
    quantum_score: Optional[QuantumScore] = None
    recommendations: List[Recommendation] = Field(default_factory=list)
    # ── Enhanced fields ──
    headers_results: List[HeadersResult] = Field(default_factory=list)
    cve_findings: List[CVEFinding] = Field(default_factory=list)
    dns_records: List[NameServerInfo] = Field(default_factory=list)
    error: Optional[str] = None


class CBOMReport(BaseModel):
    """Structured Cryptographic Bill of Materials."""
    domain: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_components: int = 0
    components: List[CryptoComponent] = Field(default_factory=list)
    risk_summary: Dict[str, int] = Field(default_factory=dict)


# ── Auth & Users ────────────────────────────────────────────────
class User(BaseModel):
    """User account model stored in MongoDB."""
    id: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    email: str
    full_name: Optional[str] = None
    hashed_password: str
    role: str = "employee"  # admin | employee
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
