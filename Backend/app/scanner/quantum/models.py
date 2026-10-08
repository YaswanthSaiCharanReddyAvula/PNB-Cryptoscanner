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
