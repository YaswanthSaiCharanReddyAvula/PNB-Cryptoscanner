"""
QuantumShield — Canonical Data Models

These models act as the central source of truth for the convergence layer,
abstracting away engine-specific details before aggregation and export.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field

from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel


class Identifier(BaseModel):
    type: str  # e.g., 'hostname', 'ip', 'url', 'port', 'service', 'purl', 'cpe', 'fingerprint', 'digest'
    value: str


class Location(BaseModel):
    type: str
    value: str


class Relationship(BaseModel):
    type: str  # e.g., 'depends_on', 'hosted_on', 'uses', 'contains'
    target_id: str


class CanonicalEvidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    source_engine: str
    source_stage: str
    observation_type: str
    target: str
    location: Optional[str] = None
    observed_at: datetime
    confidence: float = 1.0
    value: Optional[str] = None
    value_hash: Optional[str] = None
    redaction_status: str = ObservationStatus.UNKNOWN


class CanonicalFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    finding_type: str
    title: str
    description: str
    severity: RiskLevel
    confidence: float = 1.0
    status: ObservationStatus
    asset_refs: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    references: List[Dict[str, str]] = Field(default_factory=list)  # e.g., {"type": "cve", "id": "CVE-2023-XXXX"}
    timestamps: Dict[str, datetime] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)


class CanonicalAsset(BaseModel):
    asset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    asset_type: AssetType
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    identifiers: List[Identifier] = Field(default_factory=list)
    locations: List[Location] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    observed_at: datetime
    confidence: float = 1.0
    status: ObservationStatus = ObservationStatus.OBSERVED
    properties: Dict[str, Any] = Field(default_factory=dict)  # Extensible properties for specific types (crypto, cloud)


class CanonicalPackage(BaseModel):
    """Specific structured properties for packages, usually embedded in CanonicalAsset properties or maintained separately."""
    name: str
    ecosystem: Optional[str] = None
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    licenses: List[str] = Field(default_factory=list)
    directness: Optional[str] = None
    dependency_scope: Optional[str] = None
    source: Optional[str] = None
