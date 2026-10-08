"""
Phase 4 — Quantum Risk Models
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class TimeValue(BaseModel):
    value: Optional[float] = None
    unit: str = "years"
    source: str = "unknown"
    confidence: float = 1.0
    assumption: Optional[str] = None


class QuantumTimeline(BaseModel):
    Tm: TimeValue = Field(description="Migration Time")
    Tc: TimeValue = Field(description="Confidentiality / Required Protection Lifetime")
    Tq: TimeValue = Field(description="Quantum Threat Timeline")


class MoscaAssessment(BaseModel):
    margin: Optional[float] = Field(None, description="Tm + Tc - Tq")
    status: Literal[
        "NOT_APPLICABLE",
        "INSUFFICIENT_DATA",
        "SAFE_MARGIN",
        "BORDERLINE",
        "MIGRATION_REQUIRED",
        "CRITICAL_URGENCY",
    ]


class ShorAssessment(BaseModel):
    affected: bool
    vulnerability_class: str
    algorithm: str
    key_size: Optional[int] = None
    curve: Optional[str] = None


class GroverAssessment(BaseModel):
    affected: bool
    vulnerability_class: str
    algorithm: str
    effective_security_bits: Optional[int] = None


class HNDLAssessment(BaseModel):
    vulnerable_crypto: bool
    key_exchange_exposure: bool
    data_sensitivity: str
    exposure: float = 0.0
    weight: float = 1.0


class QuantumRiskAssessment(BaseModel):
    assessment_id: str
    asset_id: str
    subject_id: str
    model_version: str
    assessed_at: str

    algorithmic_risk: float
    shor_assessment: Optional[ShorAssessment] = None
    grover_assessment: Optional[GroverAssessment] = None

    timeline: QuantumTimeline
    mosca: MoscaAssessment
    hndl: HNDLAssessment

    business_criticality: str = "unknown"
    migration_complexity: str = "unknown"

    overall_quantum_risk: float
    risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
    migration_priority: Literal["P0", "P1", "P2", "P3", "MONITOR", "NONE"]

    confidence: float
    assumptions: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class HNDLSummary(BaseModel):
    exposure: float = 0.0
    classification: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]


class MoscaSummary(BaseModel):
    margin: Optional[float] = None
    status: str


class AssetQuantumRiskSummary(BaseModel):
    asset_id: str
    quantum_risk_score: float
    risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
    hndl: HNDLSummary
    mosca: MoscaSummary
    migration_priority: Literal["P0", "P1", "P2", "P3", "MONITOR", "NONE", "UNKNOWN"]
    confidence: float
    unknown_coverage: float = 0.0
    assessments: List[QuantumRiskAssessment] = Field(default_factory=list)


class ApplicationQuantumRiskSummary(BaseModel):
    application_id: str
    quantum_risk_score: float
    risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
    assets_analyzed: int
    critical_assets: int
    confidence: float
    asset_summaries: List[AssetQuantumRiskSummary] = Field(default_factory=list)


class OrganizationQuantumRiskSummary(BaseModel):
    overall_quantum_risk_score: float
    risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
    total_assets: int
    critical_assets: int
    p0_assets: int
    hndl_exposed_assets: int
    mosca_boundary_assets: int
    unknown_crypto_assets: int
    pqc_ready_assets: int
    known_coverage: float
    unknown_coverage: float
    confidence: float
