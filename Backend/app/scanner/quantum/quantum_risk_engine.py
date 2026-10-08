"""
Phase 4 — Quantum Risk Engine

Aggregates Algorithmic Vulnerability, Mosca Margin, and HNDL Exposure
to determine the final Quantum Risk Score and Migration Priority.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, Any, List

from app.scanner.quantum.models import (
    QuantumRiskAssessment,
    QuantumTimeline,
    ShorAssessment,
    GroverAssessment,
)
from app.scanner.quantum.taxonomy import QUANTUM_ALGORITHM_TAXONOMY
from app.scanner.quantum.mosca_engine import calculate_mosca_assessment
from app.scanner.quantum.hndl_engine import calculate_hndl_exposure


def determine_algorithmic_risk(alg_info: Dict[str, Any]) -> float:
    """Map quantum class to base algorithmic risk score (0-100)."""
    q_class = alg_info.get("default_quantum_class", "none")
    if q_class == "critical":
        return 90.0
    elif q_class == "high":
        return 75.0
    elif q_class == "medium":
        return 50.0
    elif q_class == "low":
        return 25.0
    return 0.0


def assess_quantum_risk(
    asset_id: str,
    algorithm_name: str,
    timeline: QuantumTimeline,
    key_size: int = None,
    key_exchange_role: bool = False,
    data_sensitivity: str = "UNKNOWN",
    business_criticality: str = "UNKNOWN",
    migration_complexity: str = "UNKNOWN",
    evidence: List[str] = None
) -> QuantumRiskAssessment:
    """
    Evaluates a single quantum subject (cryptographic primitive) and computes its quantum risk.
    """
    assumed = []
    confidence = 1.0
    is_unknown = False

    # Canonicalize the algorithm name
    alg_key = algorithm_name.upper().strip()
    alg_info = QUANTUM_ALGORITHM_TAXONOMY.get(alg_key)
    
    if not alg_info:
        is_unknown = True
        confidence = 0.2
        assumed.append(f"Algorithm {alg_key} unknown, assuming INSUFFICIENT_DATA")
        alg_info = {
            "family": "unknown",
            "quantum_attack": "unknown",
            "affected": False,
            "default_quantum_class": "unknown",
            "hndl_capable": False,
        }

    # 1. Base Algorithmic Risk
    alg_risk = determine_algorithmic_risk(alg_info)
    
    # 2. Shor/Grover Assessments
    shor_assessment = None
    grover_assessment = None
    if alg_info.get("quantum_attack") == "Shor":
        shor_assessment = ShorAssessment(
            affected=True,
            vulnerability_class=alg_info.get("default_quantum_class"),
            algorithm=alg_key,
            key_size=key_size
        )
    elif alg_info.get("quantum_attack") == "Grover":
        grover_assessment = GroverAssessment(
            affected=True,
            vulnerability_class=alg_info.get("default_quantum_class"),
            algorithm=alg_key,
            effective_security_bits=key_size // 2 if key_size else None
        )

    # 3. Mosca Assessment
    mosca = calculate_mosca_assessment(timeline)

    # 4. HNDL Assessment
    # An algorithm exposes HNDL if it is capable of it (e.g. Asymmetric) and is used for Key Exchange
    is_vulnerable_kex = alg_info.get("hndl_capable", False) and key_exchange_role
    hndl = calculate_hndl_exposure(is_vulnerable_kex, data_sensitivity, timeline)

    # 5. Calculate Overall Quantum Risk
    # Base risk modified by HNDL weight. Add temporal urgency penalties.
    overall_risk = alg_risk * hndl.weight
    
    if mosca.status == "CRITICAL_URGENCY":
        overall_risk += 15
    elif mosca.status == "MIGRATION_REQUIRED":
        overall_risk += 10
    elif mosca.status == "BORDERLINE":
        overall_risk += 5
        
    overall_risk = min(max(overall_risk, 0.0), 100.0)
    if is_unknown:
        overall_risk = 0.0
        risk_tier = "UNKNOWN"
        migration_priority = "UNKNOWN"
    else:
        # 6. Determine Risk Tier
        if overall_risk >= 85:
            risk_tier = "CRITICAL"
        elif overall_risk >= 70:
            risk_tier = "HIGH"
        elif overall_risk >= 40:
            risk_tier = "MEDIUM"
        elif overall_risk >= 1:
            risk_tier = "LOW"
        else:
            risk_tier = "SAFE"

        # 7. Migration Priority
        # Business Criticality and Migration Complexity could shift priority.
        # A simple mapping for now.
        if mosca.status in ("CRITICAL_URGENCY", "MIGRATION_REQUIRED") or risk_tier == "CRITICAL":
            migration_priority = "P0"
        elif risk_tier == "HIGH":
            migration_priority = "P1"
        elif risk_tier == "MEDIUM":
            migration_priority = "P2"
        elif risk_tier == "LOW":
            migration_priority = "P3"
        else:
            migration_priority = "MONITOR"

    # Assemble assessment
    return QuantumRiskAssessment(
        assessment_id=f"qra-{uuid.uuid4()}",
        asset_id=asset_id,
        subject_id=f"sub-{alg_key.lower()}",
        model_version="4.0.0",
        assessed_at=datetime.now(timezone.utc).isoformat(),
        
        algorithmic_risk=alg_risk,
        shor_assessment=shor_assessment,
        grover_assessment=grover_assessment,
        
        timeline=timeline,
        mosca=mosca,
        hndl=hndl,
        
        business_criticality=business_criticality,
        migration_complexity=migration_complexity,
        
        overall_quantum_risk=round(overall_risk, 2),
        risk_tier=risk_tier,
        migration_priority=migration_priority,
        
        confidence=confidence,
        assumptions=assumed,
        evidence=evidence or []
    )
