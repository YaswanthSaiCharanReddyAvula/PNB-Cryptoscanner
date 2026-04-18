"""
QuantumShield — Scanner Data Models

Shared Pydantic models used across all scanner subsystems.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Pipeline helpers ──────────────────────────────────────────────────

class StageResult(BaseModel):
    status: str
    data: dict = Field(default_factory=dict)
    error: Optional[str] = None
    request_count: int = 0
    duration_seconds: float = 0.0


class StageMetrics(BaseModel):
    name: str
    status: str
    duration: float = 0.0
    request_count: int = 0
    error: Optional[str] = None
    reason: Optional[str] = None
    summary: dict = Field(default_factory=dict)
    preview: dict = Field(default_factory=dict)


# ── Recon ─────────────────────────────────────────────────────────────

class DNSRecord(BaseModel):
    hostname: str
    record_type: str  # A / AAAA / MX / TXT / CNAME / SOA / NS / SRV / CAA / PTR
    value: str
    ttl: int


class WhoisInfo(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    nameservers: list[str] = Field(default_factory=list)
    dnssec: bool = False


class ReconResult(BaseModel):
    subdomains: list[str] = Field(default_factory=list)
    ip_map: dict[str, list[str]] = Field(default_factory=dict)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    ct_hosts: list[str] = Field(default_factory=list)
    reverse_dns: dict[str, str] = Field(default_factory=dict)
    zone_transfer_vulnerable: bool = False
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None


# ── Port scanning ─────────────────────────────────────────────────────

class PortResult(BaseModel):
    ip: str
    port: int
    state: str  # open / filtered / closed / error


# ── Service & OS fingerprinting ───────────────────────────────────────

class ServiceFingerprint(BaseModel):
    host: str
    port: int
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[str] = None
    protocol_category: Optional[str] = None
    confidence: str = "medium"


class ASNInfo(BaseModel):
    asn: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    org: Optional[str] = None


class OSFingerprint(BaseModel):
    host: str
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    os_confidence: str = "low"
    runtime: Optional[str] = None
    container_likely: bool = False
    container_evidence: list[str] = Field(default_factory=list)
    evidence_sources: list[str] = Field(default_factory=list)


class AdvancedOSFingerprint(BaseModel):
    host: str
    tier: str = ""
    os_match: Optional[str] = None
    match_confidence: float = 0.0
    tcp_window_size: Optional[int] = None
    ttl_observed: Optional[int] = None
    mss_observed: Optional[int] = None
    df_bit: Optional[bool] = None
    window_scale: Optional[int] = None
    timestamp_present: Optional[bool] = None
    options_order: Optional[str] = None
    evidence_sources: list[str] = Field(default_factory=list)


# ── TLS / Crypto ──────────────────────────────────────────────────────

class CipherDetail(BaseModel):
    name: str
    kex: Optional[str] = None
    auth: Optional[str] = None
    encryption: Optional[str] = None
    mac: Optional[str] = None
    bits: Optional[int] = None
    pfs: bool = False
    pqc: bool = False
    strength: str = "unknown"


class CertificateDetail(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_until_expiry: Optional[int] = None
    expired: bool = False
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    sig_algorithm: Optional[str] = None
    sans: list[str] = Field(default_factory=list)
    is_self_signed: bool = False
    fingerprint_sha256: Optional[str] = None
    quantum_vulnerable: bool = True


class TLSProfile(BaseModel):
    host: str
    port: int
    tls_versions_supported: dict[str, bool] = Field(default_factory=dict)
    accepted_ciphers: list[CipherDetail] = Field(default_factory=list)
    negotiated_cipher: Optional[str] = None
    cert_chain: list[CertificateDetail] = Field(default_factory=list)
    leaf_cert: Optional[CertificateDetail] = None
    forward_secrecy: bool = False
    ocsp_stapling: Optional[bool] = None
    starttls_protocol: Optional[str] = None
    pqc_signals: list[str] = Field(default_factory=list)
    confidence: str = "high"


class CryptoFinding(BaseModel):
    host: str
    port: Optional[int] = None
    component: str
    algorithm: str
    quantum_risk: str = ""
    threat_vector: str = ""
    hndl_risk: str = ""
    nist_recommendation: str = ""
    evidence: str = ""
    confidence: str = "high"


# ── Infrastructure intel ──────────────────────────────────────────────

class InfrastructureIntel(BaseModel):
    host: str
    cdn_provider: Optional[str] = None
    cdn_evidence: list[str] = Field(default_factory=list)
    waf_detected: bool = False
    waf_provider: Optional[str] = None
    waf_evidence: list[str] = Field(default_factory=list)
    reverse_proxy: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_evidence: list[str] = Field(default_factory=list)
    confidence: str = "medium"


class TechFingerprint(BaseModel):
    host: str
    category: str = ""
    name: str = ""
    version: Optional[str] = None
    confidence: str = "medium"
    evidence: Optional[str] = None
    cpe: Optional[str] = None


# ── Web-app profiling ─────────────────────────────────────────────────

class HeaderAuditResult(BaseModel):
    present: bool = False
    value: Optional[str] = None
    compliant: bool = False
    issue: Optional[str] = None


class CookieAudit(BaseModel):
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    path: Optional[str] = None
    issues: list[str] = Field(default_factory=list)


class CORSAudit(BaseModel):
    origin_tested: str = ""
    acao: Optional[str] = None
    credentials_allowed: bool = False
    is_permissive: bool = False
    risk: str = "low"


class APISchemaResult(BaseModel):
    path: str
    status_code: int = 0
    is_schema: bool = False
    documented_endpoints: list[str] = Field(default_factory=list)


class WellKnownResult(BaseModel):
    path: str
    status_code: int = 0
    found: bool = False
    content_preview: Optional[str] = None


class WebAppProfile(BaseModel):
    host: str
    url: str = ""
    status_code: Optional[int] = None
    security_headers: dict[str, HeaderAuditResult] = Field(default_factory=dict)
    header_score: float = 0.0
    cookies: list[CookieAudit] = Field(default_factory=list)
    cors: Optional[CORSAudit] = None
    api_schemas_found: list[APISchemaResult] = Field(default_factory=list)
    well_known_results: list[WellKnownResult] = Field(default_factory=list)
    info_leaks: list[str] = Field(default_factory=list)


# ── Hidden-asset discovery ────────────────────────────────────────────

class HiddenFinding(BaseModel):
    host: str
    path: str
    status_code: int = 0
    discovery_source: str = ""
    finding_type: str = ""
    risk: str = "low"
    confidence: float = 0.0
    evidence: Optional[str] = None


# ── Vulnerability assessment ──────────────────────────────────────────

class VulnFinding(BaseModel):
    host: str
    vuln_id: str = ""
    name: str
    severity: str = "info"
    category: str = ""
    evidence: Optional[str] = None
    confidence: float = 0.0
    remediation: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    affected_component: Optional[str] = None
    quantum_relevance: bool = False


# ── Risk scoring ──────────────────────────────────────────────────────

class RiskDriver(BaseModel):
    dimension: str
    finding: str
    impact: str = ""
    confidence: str = ""
    remediation: Optional[str] = None


class AssetRiskScore(BaseModel):
    host: str
    overall_score: float = 0.0
    risk_level: str = "unknown"
    dimension_scores: dict[str, float] = Field(default_factory=dict)
    top_risk_drivers: list[RiskDriver] = Field(default_factory=list)
    remediation_priority: int = 0


# ── Asset graph ───────────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    node_type: str
    label: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str = ""
    weight: float = 1.0


class AssetGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# ── Scan diff ─────────────────────────────────────────────────────────

class ScanDiff(BaseModel):
    new_assets: list[str] = Field(default_factory=list)
    removed_assets: list[str] = Field(default_factory=list)
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)
    score_delta: float = 0.0


# ── Crawl / Fuzz ─────────────────────────────────────────────────────

class FormData(BaseModel):
    page_url: str
    action: Optional[str] = None
    method: str = "GET"
    fields: list[dict[str, Any]] = Field(default_factory=list)


class ParamData(BaseModel):
    host: str
    url: str
    name: str
    original_value: Optional[str] = None


class CrawlResult(BaseModel):
    pages_visited: int = 0
    forms: list[FormData] = Field(default_factory=list)
    params: list[ParamData] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class FuzzFinding(BaseModel):
    host: str
    url: str
    parameter: str = ""
    payload_type: str = ""
    payload: str = ""
    detection: str = ""
    evidence: Optional[str] = None
    severity: str = "info"
    confidence: float = 0.0


class FuzzConfig(BaseModel):
    max_params: int = 10
    max_payloads: int = 3
    max_forms: int = 5


# ── Exploit chains ───────────────────────────────────────────────────

class ExploitChain(BaseModel):
    chain_id: str
    name: str
    severity: str = "info"
    description: str = ""
    narrative: str = ""
    steps: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    remediation: Optional[str] = None


# ── GraphQL ───────────────────────────────────────────────────────────

class GraphQLFinding(BaseModel):
    endpoint: str
    finding: str
    severity: str = "info"
    evidence: Optional[str] = None
    confidence: float = 0.0
    schema_types: list[str] = Field(default_factory=list)


# ── Behavioral ────────────────────────────────────────────────────────

class BehavioralFinding(BaseModel):
    host: str
    test: str
    evidence: Optional[str] = None
    severity: str = "info"
    confidence: float = 0.0
    implication: Optional[str] = None


# ── Browser-based scanning ───────────────────────────────────────────

class DOMFinding(BaseModel):
    url: str
    finding_type: str
    evidence: Optional[str] = None
    severity: str = "info"
    confidence: float = 0.0


class InterceptedRequest(BaseModel):
    url: str
    method: str = "GET"
    resource_type: Optional[str] = None


class BrowserCrawlResult(BaseModel):
    pages_rendered: int = 0
    js_discovered_routes: list[str] = Field(default_factory=list)
    dom_findings: list[DOMFinding] = Field(default_factory=list)
    intercepted_api_calls: list[InterceptedRequest] = Field(default_factory=list)


class ValidatedXSS(BaseModel):
    url: str
    parameter: str
    payload: str = ""
    execution_confirmed: bool = False
    severity: str = "high"
    confidence: float = 0.0
    evidence: Optional[str] = None


class AuthFlowResult(BaseModel):
    url: str
    login_form_detected: bool = False
    findings: list[str] = Field(default_factory=list)
    confidence: float = 0.0


# ── Adaptive decision engine ─────────────────────────────────────────

class AdaptiveAction(BaseModel):
    action: str
    target: str = ""
    reason: str = ""
    priority: int = 5
    llm_analysis: str = ""


class AdaptiveDecisionLog(BaseModel):
    stage: str
    findings_summary_hash: str = ""
    llm_raw_response: str = ""
    parsed_actions: list[AdaptiveAction] = Field(default_factory=list)
    actions_executed: list[str] = Field(default_factory=list)
    actions_rejected: list[str] = Field(default_factory=list)
    timestamp: Optional[datetime] = None


# ── Host-level scheduling ────────────────────────────────────────────

class HostPriority(BaseModel):
    host: str = ""
    score: int = 0
    tier: str = "standard"
    deep_scan: bool = False
    browser_scan: bool = False
    fuzz_depth: str = "light"


class HostRateState(BaseModel):
    total_requests: int = 0
    rate_limit_hits: int = 0
    waf_blocks: int = 0
    timeouts: int = 0
    current_delay: float = 0.0
    concurrency_reduction: int = 0
    waf_triggered: bool = False
    response_times: list[float] = Field(default_factory=list)


# ── Aggregate intelligence ───────────────────────────────────────────

class AssetIntelligence(BaseModel):
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    reverse_dns: Optional[str] = None
    asn: Optional[ASNInfo] = None
    open_ports: list[PortResult] = Field(default_factory=list)
    services: list[ServiceFingerprint] = Field(default_factory=list)
    os_fingerprint: Optional[OSFingerprint] = None
    tls_profiles: list[TLSProfile] = Field(default_factory=list)
    crypto_findings: list[CryptoFinding] = Field(default_factory=list)
    technologies: list[TechFingerprint] = Field(default_factory=list)
    infrastructure: Optional[InfrastructureIntel] = None
    web_profile: Optional[WebAppProfile] = None
    hidden_findings: list[HiddenFinding] = Field(default_factory=list)
    vuln_findings: list[VulnFinding] = Field(default_factory=list)
    risk_score: Optional[AssetRiskScore] = None
    evidence_sources: list[str] = Field(default_factory=list)
    overall_confidence: str = "medium"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ScanIntelligenceReport(BaseModel):
    scan_id: str
    domain: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scanner_version: str = ""
    scan_config: dict[str, Any] = Field(default_factory=dict)
    assets: list[AssetIntelligence] = Field(default_factory=list)
    quantum_score: Optional[float] = None
    estate_risk_score: float = 0.0
    estate_risk_level: str = "unknown"
    estate_tier: str = ""
    asset_graph: Optional[AssetGraph] = None
    dns_records: list[DNSRecord] = Field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    ct_entries: list[str] = Field(default_factory=list)
    cbom: list[CryptoFinding] = Field(default_factory=list)
    all_findings: list[VulnFinding] = Field(default_factory=list)
    top_findings: list[VulnFinding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    diff: Optional[ScanDiff] = None
    executive_summary: str = ""
    technical_summary: str = ""
    total_assets: int = 0
    total_ports: int = 0
    total_services: int = 0
    total_findings: int = 0
    scan_duration_seconds: float = 0.0


# ── Scope guard (plain class, not a Pydantic model) ─────────────────

class ScopeGuard:
    """Prevents the scanner from straying outside the target domain."""

    def __init__(self, root_domain: str, allowed_suffixes: list[str] | None = None):
        self.root_domain = root_domain.lower().strip(".")
        self.allowed_suffixes: list[str] = [
            s.lower().strip(".") for s in (allowed_suffixes or [self.root_domain])
        ]
        self._resolved_ips: set[str] = set()

    def is_in_scope(self, target: str) -> bool:
        target = target.lower().strip(".").strip()
        if target in self._resolved_ips:
            return True
        return any(
            target == suffix or target.endswith(f".{suffix}")
            for suffix in self.allowed_suffixes
        )

    def add_resolved_ip(self, ip: str) -> None:
        self._resolved_ips.add(ip.strip())
