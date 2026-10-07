"""
QuantumShield — Cloud Domain Foundation Models (Phases 1 & 2)

Normalized data models for representing cloud infrastructure targets,
resources, and cryptographic assets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Scope and credential boundary (Phase 2) ──────────────────────────

class CredentialReference(BaseModel):
    """
    Reference to a credential for acquiring access.
    NEVER stores raw credential material.
    """
    credential_type: str = "environment"  # e.g., environment, profile, assumed_role, managed_identity
    reference_id: str = ""                # e.g., profile name, role ARN
    provider: str = ""


class CloudScopePolicy(BaseModel):
    """Controls what the cloud audit engine is allowed to scan."""
    providers: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)          # account/subscription/project IDs
    regions: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    max_concurrency: int = 5
    max_retries: int = 3
    page_limit: int = 100


class CloudAuditTarget(BaseModel):
    """The normalized target specification for a cloud scan."""
    provider: str
    target_ids: list[str] = Field(default_factory=list)  # accounts/subscriptions/projects
    regions: list[str] = Field(default_factory=list)
    scope: CloudScopePolicy = Field(default_factory=CloudScopePolicy)
    credential_reference: Optional[CredentialReference] = None
    authorization_mode: str = "read_only"


class IdentityContext(BaseModel):
    """The identity established for the current cloud session."""
    provider: str
    account_id: str
    principal: str
    principal_type: str
    identity_source: str = ""
    tenant: Optional[str] = None
    organization: Optional[str] = None
    is_valid: bool = False


# ── Enums ─────────────────────────────────────────────────────────────

class CloudPermissionState(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    PERMISSION_DENIED = "permission_denied"
    AUTHENTICATION_FAILED = "authentication_failed"
    NOT_SUPPORTED = "not_supported"
    RATE_LIMITED = "rate_limited"
    SERVICE_ERROR = "service_error"
    UNKNOWN = "unknown"


# ── Cloud domain foundation (Phase 1) ────────────────────────────────

class CloudEvidence(BaseModel):
    evidence_id: str
    provider: str
    account_id: str
    region: str
    resource_id: str
    resource_type: str
    observation_type: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    collector: str
    confidence: str = "high"
    permission_status: CloudPermissionState = CloudPermissionState.SUCCESS


class CloudResource(BaseModel):
    provider: str
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    parent: Optional[str] = None
    tags: dict[str, str] = Field(default_factory=dict)
    state: str = "active"
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CloudCryptoAsset(BaseModel):
    provider: str
    resource_id: str
    asset_type: str          # e.g., kms_key, certificate
    algorithm: str           # e.g., RSA_2048, ECC_NIST_P256
    key_size: Optional[int] = None
    curve: Optional[str] = None
    purpose: str = ""
    creation_time: Optional[datetime] = None
    expiration_time: Optional[datetime] = None
    rotation_enabled: Optional[bool] = None
    last_rotation: Optional[datetime] = None
    usage_state: str = "unknown"
    owner: str = ""
    scope: str = ""


class CloudSecretObservation(BaseModel):
    provider: str
    resource_id: str
    name: str
    secret_type: str
    creation_time: Optional[datetime] = None
    last_changed: Optional[datetime] = None
    rotation_enabled: Optional[bool] = None
    encryption_key: Optional[str] = None
    access_scope: str = ""


class CloudFinding(BaseModel):
    finding_id: str
    provider: str
    account_id: str
    region: str
    resource_id: str
    resource_type: str
    finding_type: str
    severity: str = "medium"
    confidence: str = "high"
    evidence_ids: list[str] = Field(default_factory=list)
    remediation: str = ""


class CloudCoverage(BaseModel):
    provider: str
    accounts_scanned: int = 0
    regions_scanned: int = 0
    resources_discovered: int = 0
    resources_inspected: int = 0
    resources_skipped: int = 0
    permission_denials: int = 0
    api_errors: int = 0
    unsupported_services: int = 0
