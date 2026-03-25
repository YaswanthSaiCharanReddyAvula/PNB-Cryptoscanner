"""
QuantumShield — Pydantic Schemas

Request / response models for all API v2 endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


# ── Auth ─────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: Union[EmailStr, str]   # accepts both email and plain username
    password: str
    username: Optional[str] = None  # ignored, kept for frontend compatibility


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    message: str


# ── Users ────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Dashboard ────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_assets: int
    public_web_apps: int
    apis: int
    servers: int
    expiring_certificates: int
    high_risk_assets: int


# ── Assets ───────────────────────────────────────────────────────

class AssetOut(BaseModel):
    id: UUID
    asset_name: str
    url: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    type: Optional[str] = None
    owner: Optional[str] = None
    risk: Optional[str] = None
    certificate_status: Optional[str] = None
    key_length: Optional[int] = None
    last_scan: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AssetOut]


# ── Name Servers ─────────────────────────────────────────────────

class NameServerOut(BaseModel):
    id: UUID
    hostname: str
    type: str
    ip_address: Optional[str] = None
    ttl: Optional[int] = None

    model_config = {"from_attributes": True}


# ── Crypto ───────────────────────────────────────────────────────

class CryptoRecordOut(BaseModel):
    id: UUID
    asset: str
    key_length: Optional[int] = None
    cipher_suite: Optional[str] = None
    tls_version: Optional[str] = None
    certificate_authority: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Asset Inventory ──────────────────────────────────────────────

class AssetInventoryOut(BaseModel):
    id: UUID
    detection_date: Optional[datetime] = None
    ip_address: Optional[str] = None
    ports: Optional[str] = None
    subnets: Optional[str] = None
    asn: Optional[str] = None
    net_name: Optional[str] = None
    location: Optional[str] = None
    company: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Asset Discovery Graph ─────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    label: Optional[str] = None
    type: Optional[str] = None


class GraphEdge(BaseModel):
    source: str
    target: str


class AssetDiscoveryGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ── CBOM ─────────────────────────────────────────────────────────

class CBOMSummaryOut(BaseModel):
    total_applications: int
    sites_surveyed: int
    active_certificates: int
    weak_cryptography: int
    certificate_issues: int


class KeyLengthDist(BaseModel):
    key_length: int
    count: int


class CADist(BaseModel):
    certificate_authority: str
    count: int


class ProtocolDist(BaseModel):
    tls_version: str
    count: int


class CipherUsage(BaseModel):
    name: str
    count: int
    weak: bool = False   # True if cipher is known-weak (RC4, DES, MD5, NULL)


class CBOMCharts(BaseModel):
    key_length_distribution: List[KeyLengthDist]
    top_certificate_authorities: List[CADist]
    encryption_protocols: List[ProtocolDist]
    cipher_usage: List[CipherUsage] = []


# ── PQC Posture ──────────────────────────────────────────────────

class VulnerableAlgorithm(BaseModel):
    name: str
    count: int
    risk: str


class AssetPQCStatus(BaseModel):
    asset_name: str
    ip_address: Optional[str] = None
    pqc_supported: bool
    tls_version: Optional[str] = None
    risk: Optional[str] = None
    score: Optional[int] = None
    status: str  # "Elite-PQC" | "Standard" | "Legacy" | "Critical"


class PQCPosture(BaseModel):
    vulnerable_algorithms: List[VulnerableAlgorithm]
    pqc_ready_assets: int
    migration_score: float
    # Classification grade breakdown (prototype requirement)
    elite_pqc_pct: float = 0.0
    standard_pct: float = 0.0
    legacy_pct: float = 0.0
    critical_pct: float = 0.0
    critical_apps: int = 0
    # Elite/Standard/Legacy asset counts
    elite_count: int = 0
    standard_count: int = 0
    legacy_count: int = 0
    # Per-asset PQC status list
    asset_pqc_status: List[AssetPQCStatus] = []
    # Improvement recommendations
    recommendations: List[str] = []


# ── Cyber Rating ─────────────────────────────────────────────────

class RiskFactor(BaseModel):
    factor: str
    severity: str
    detail: str


class TierInfo(BaseModel):
    status: str
    range: str


class PerURLScore(BaseModel):
    url: str
    score: int


class CyberRating(BaseModel):
    score: int                          # out of 1000
    max_score: int = 1000
    tier: str                           # "Legacy" | "Standard" | "Elite-PQC"
    tier_description: str
    grade: str                          # A-F (kept for compatibility)
    risk_factors: List[RiskFactor]
    tiers: List[TierInfo]
    per_url_scores: List[PerURLScore] = []


# ── Reports ──────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    format: str = Field(default="json", pattern="^(json|xml|csv|pdf)$")
    filters: Optional[Dict[str, Any]] = None
    scheduled_at: Optional[datetime] = None  # for scheduler endpoint


class ReportResponse(BaseModel):
    report_id: UUID
    type: str
    format: str
    content: Optional[str] = None   # inlined JSON/XML/CSV or download URL for PDF
    created_at: datetime

    model_config = {"from_attributes": True}
