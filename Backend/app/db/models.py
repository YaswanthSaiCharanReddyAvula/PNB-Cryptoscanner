"""
QuantumShield — Pydantic Data Models

Defines the request/response schemas and internal data structures
used across the scanning pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


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
    # Phase 2: optional org metadata (from inventory import or UI)
    owner: Optional[str] = None
    environment: Optional[str] = None  # e.g. prod, staging, dev
    criticality: Optional[str] = None  # e.g. low, medium, high, critical
    # Phase: asset bucketing (hosting / surface / mobile gateways) — filled after TLS + HTTP probes
    buckets: List[str] = Field(default_factory=list)
    hosting_hint: Optional[str] = None  # first_party | third_party_cdn | saas_likely | cloud_provider | unknown
    surface: Optional[str] = None  # web | api | mail | vpn | rdp | unknown
    classification_attributes: Dict[str, Any] = Field(default_factory=dict)


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
    # ── Phase 1: audit signals (string-based; not proof of deployed PQC libraries) ──
    tls_modern: bool = False
    hybrid_key_exchange: bool = False
    pqc_kem_observed: bool = False
    pqc_signal_hints: List[str] = Field(default_factory=list)


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


class ActiveVulnFinding(BaseModel):
    """Finding from optional active scanner (e.g. Nuclei), distinct from crypto/TLS CVE mapping."""

    source: str = "nuclei"
    template_id: Optional[str] = None
    name: str = ""
    severity: str = "info"  # info, low, medium, high, critical
    host: str = ""
    url: Optional[str] = None
    matcher_name: Optional[str] = None


class CryptoComponent(BaseModel):
    """A single cryptographic component in the CBOM."""
    name: str
    category: AlgorithmCategory
    key_size: Optional[int] = None
    usage_context: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    quantum_status: QuantumStatus = QuantumStatus.VULNERABLE
    details: Optional[str] = None
    # ── Phase 1: traceability per scan host ──
    host: Optional[str] = None
    # Primary quantum threat: shor (asymmetric), grover (symmetric/hash), hndl (protocol capture)
    primary_quantum_threat: Optional[str] = None


class QuantumScoreBreakdown(BaseModel):
    """Per-category scores that feed into the aggregate."""
    key_exchange_score: float = 0
    signature_score: float = 0
    cipher_score: float = 0
    protocol_score: float = 0
    hash_score: float = 50


class QuantumScore(BaseModel):
    """Overall Quantum Readiness Score."""
    score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    breakdown: QuantumScoreBreakdown
    summary: str = ""
    # Observability / audit (Phase 4)
    confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    catalog_version: str = ""
    drivers: List[str] = Field(default_factory=list)
    aggregation: str = "estate_weakest"


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
    # Org-wide inventory (Discovery phase extensions): explicit targets + registered catalog
    additional_seed_hosts: Optional[List[str]] = Field(
        default=None,
        description="Extra hostnames to port-scan and assess (CMDB/manual/Git runner output, etc.)",
    )
    merge_registered_inventory: bool = Field(
        default=False,
        description="If true, merge hosts from /inventory/sources/import for this scan domain",
    )

    @field_validator("additional_seed_hosts")
    @classmethod
    def normalize_seeds(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if not v:
            return None
        if len(v) > 200:
            raise ValueError("additional_seed_hosts: maximum 200 entries")
        out: List[str] = []
        for x in v:
            s = str(x).strip().lower()
            if s and s not in out:
                out.append(s)
        return out or None

    # Controller (UI): when unset, server uses settings.MAX_SUBDOMAINS / TOOL_TIMEOUT
    max_subdomains: Optional[int] = Field(
        default=None,
        ge=1,
        le=500,
        description="Cap passive subdomain enumeration before DNSX/HTTPX/nmap",
    )
    execution_time_limit_seconds: Optional[int] = Field(
        default=None,
        ge=10,
        le=900,
        description="Per subprocess cap for discovery tools and TLS helpers (sslscan/openssl/zgrab/testssl)",
    )


class BatchScanRequest(BaseModel):
    """Trigger multiple domain scans (portfolio / org sweep)."""
    domains: List[str]
    include_subdomains: bool = True
    ports: Optional[str] = None
    merge_registered_inventory: bool = False
    max_subdomains: Optional[int] = Field(default=None, ge=1, le=500)
    execution_time_limit_seconds: Optional[int] = Field(default=None, ge=10, le=900)


class RegisteredAssetItem(BaseModel):
    """One row from CMDB, cloud export, K8s ingress list, etc."""
    host: str = Field(..., min_length=1, max_length=253)
    parent_domain: Optional[str] = Field(
        default=None,
        max_length=253,
        description="Scope for merge_registered_inventory (defaults to import-level parent_domain)",
    )
    external_id: Optional[str] = Field(default=None, max_length=256)
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    notes: Optional[str] = None


class InventorySourceImport(BaseModel):
    """Bulk register assets from an external source (connector or file ingest)."""
    source: str = Field(
        ...,
        min_length=1,
        max_length=48,
        description="Logical source: cmdb, cloud, k8s, git, pki, kms, manual, other",
    )
    parent_domain: Optional[str] = Field(
        default=None,
        max_length=253,
        description="Default parent zone e.g. bank.in for all items",
    )
    items: List[RegisteredAssetItem] = Field(..., min_length=1, max_length=500)


class SbomIngestRequest(BaseModel):
    """Store a CycloneDX/SPDX-style JSON blob for a host (SAST/supply-chain path)."""
    host: str = Field(..., min_length=1, max_length=253)
    scan_domain: Optional[str] = Field(default=None, max_length=253)
    format: str = Field(default="cyclonedx", max_length=32)
    document: Dict[str, Any] = Field(..., description="Parsed SBOM root object")


class AssetMetadataUpdate(BaseModel):
    """Upsert per-host metadata (keyed by FQDN / discovered subdomain)."""
    host: str
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None


class SimulateQuantumRequest(BaseModel):
    """What-if projection against latest completed scan (Phase 3)."""
    domain: Optional[str] = None
    assume_tls_13_all: bool = False
    assume_pqc_hybrid_kem: bool = False


# ── Phase 4: Admin — policy & integrations ───────────────────────


class OrgCryptoPolicyUpdate(BaseModel):
    """Upsert org crypto policy (stored as a single document)."""
    min_tls_version: Optional[str] = None  # e.g. "1.2", "1.3"
    require_forward_secrecy: Optional[bool] = None
    pqc_readiness_target: Optional[str] = None
    policy_notes: Optional[str] = None


class IntegrationSettingsUpdate(BaseModel):
    """Outbound integration endpoints (full URLs stored server-side)."""
    outbound_webhook_url: Optional[str] = None
    notify_on_scan_complete: Optional[bool] = None
    slack_webhook_url: Optional[str] = None
    jira_webhook_url: Optional[str] = None


class ExportAuditLogCreate(BaseModel):
    """Client-recorded export (e.g. browser download of roadmap JSON)."""
    export_type: str = Field(..., min_length=1, max_length=80)
    domain: Optional[str] = None


class ReportScheduleDelivery(BaseModel):
    email_enabled: bool = False
    download_enabled: bool = True
    email_to: List[str] = Field(default_factory=list)


class ReportScheduleCreate(BaseModel):
    domain: Optional[str] = None
    cadence: Literal["daily", "weekly", "monthly"] = "daily"
    hour_utc: int = Field(6, ge=0, le=23)
    minute_utc: int = Field(0, ge=0, le=59)
    enabled: bool = True
    delivery: ReportScheduleDelivery


class ReportSchedulePatch(BaseModel):
    domain: Optional[str] = None
    cadence: Optional[Literal["daily", "weekly", "monthly"]] = None
    hour_utc: Optional[int] = Field(None, ge=0, le=23)
    minute_utc: Optional[int] = Field(None, ge=0, le=59)
    enabled: Optional[bool] = None
    delivery: Optional[ReportScheduleDelivery] = None


class AiRoadmapPlanBody(BaseModel):
    domain: str = Field(..., min_length=1, max_length=500)
    constraints: Optional[Dict[str, Any]] = None


class AiCopilotChatBody(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    domain: Optional[str] = None


# ── In-app notifications (employee → admin) ──────────────────────

NotificationCategory = Literal["general", "access", "scan", "other"]


class NotificationCreate(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=8000)
    category: NotificationCategory = "general"


class NotificationMarkRead(BaseModel):
    read: bool = True


class NotificationOut(BaseModel):
    notification_id: str
    from_user_id: str
    from_email: str
    from_name: Optional[str] = None
    to_role: str = "admin"
    subject: str
    body: str
    category: str
    created_at: datetime
    read_at: Optional[datetime] = None
    read_by: Optional[str] = None


# ── Phase 5: Migration tasks & waivers ─────────────────────────────


class MigrationTaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    domain: Optional[str] = None
    host: Optional[str] = None
    wave: int = Field(default=1, ge=1, le=5)
    priority: str = "medium"
    status: str = "open"
    due_date: Optional[str] = None
    owner: Optional[str] = None


class MigrationTaskUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    domain: Optional[str] = None
    host: Optional[str] = None
    wave: Optional[int] = Field(None, ge=1, le=5)
    priority: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[str] = None
    owner: Optional[str] = None


class WaiverCreate(BaseModel):
    requestor: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    expiry: Optional[str] = None
    impacted_assets: List[str] = Field(default_factory=list)
    status: str = "pending"


class WaiverUpdate(BaseModel):
    requestor: Optional[str] = None
    reason: Optional[str] = None
    expiry: Optional[str] = None
    impacted_assets: Optional[List[str]] = None
    status: Optional[str] = None


class SeedTasksFromBacklogBody(BaseModel):
    domain: Optional[str] = None
    limit: int = Field(default=12, ge=1, le=80)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResult(BaseModel):
    """Full result of a scan stored in MongoDB."""
    scan_id: Optional[str] = None
    batch_id: Optional[str] = None
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
    vuln_findings: List[ActiveVulnFinding] = Field(default_factory=list)
    dns_records: List[NameServerInfo] = Field(default_factory=list)
    error: Optional[str] = None


class CBOMReport(BaseModel):
    """Structured Cryptographic Bill of Materials."""
    schema_version: str = "1.0.0"
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
