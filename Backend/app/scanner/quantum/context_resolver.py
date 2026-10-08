"""
Phase 4 — Quantum Context Resolver

Adapts Phase 3 Canonical Assets into Quantum Assessment subjects,
resolving temporal constraints (Tm, Tc, Tq) from policies or properties.
"""

from typing import List, Dict, Any, Optional

from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalProperty
from app.scanner.quantum.models import (
    QuantumTimeline,
    TimeValue,
    QuantumRiskAssessment,
)
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk


def _resolve_timeline(asset: CanonicalAsset, scenario: str = "baseline") -> QuantumTimeline:
    """
    Extracts or defaults Tm, Tc, Tq for an asset based on properties or policies.
    """
    # 1. Tq (Quantum Threat Timeline)
    # Typically comes from a global scenario, but we allow property overrides.
    tq_val = 15.0
    if scenario == "optimistic":
        tq_val = 20.0
    elif scenario == "aggressive":
        tq_val = 10.0

    tq = TimeValue(
        value=tq_val,
        unit="years",
        source=f"scenario_{scenario}",
        confidence=0.5,
        assumption="Global scenario assumption"
    )

    # 2. Tc (Confidentiality Lifetime)
    # Default policy: assume 5 years unless tagged.
    tc_val = 5.0
    tc_source = "default_policy"
    
    # Try to extract data classification from properties
    if "data_classification" in asset.properties:
        prop = asset.properties["data_classification"]
        if isinstance(prop, CanonicalProperty):
            val = str(prop.canonical_value).upper()
        else:
            val = str(prop).upper()
            
        mapping = {
            "PUBLIC": 0.0,
            "INTERNAL": 1.0,
            "CONFIDENTIAL": 5.0,
            "HIGHLY_SENSITIVE": 10.0,
            "LONG_TERM_SECRET": 20.0
        }
        if val in mapping:
            tc_val = mapping[val]
            tc_source = "asset_property:data_classification"

    tc = TimeValue(
        value=tc_val,
        unit="years",
        source=tc_source,
        confidence=0.8,
        assumption="Policy mapping from data classification"
    )

    # 3. Tm (Migration Time)
    # Default policy: assume 2 years.
    tm_val = 2.0
    tm_source = "default_policy"
    
    tm = TimeValue(
        value=tm_val,
        unit="years",
        source=tm_source,
        confidence=0.7,
        assumption="Standard system migration timeline"
    )

    return QuantumTimeline(Tm=tm, Tc=tc, Tq=tq)


def _get_property_val(prop: Any) -> str:
    if isinstance(prop, CanonicalProperty):
        return str(prop.canonical_value)
    return str(prop)


def resolve_asset_quantum_risk(
    asset: CanonicalAsset, scenario: str = "baseline"
) -> List[QuantumRiskAssessment]:
    """
    Reads a canonical asset, identifies cryptographic properties, and generates
    a list of QuantumRiskAssessments for each cryptographic subject.
    """
    assessments = []
    
    # Resolve the shared temporal context for this asset
    timeline = _resolve_timeline(asset, scenario)
    
    # Data sensitivity for HNDL weight
    sensitivity = "UNKNOWN"
    if "data_classification" in asset.properties:
        sensitivity = _get_property_val(asset.properties["data_classification"]).upper()
        
    business_criticality = "UNKNOWN"
    if "business_criticality" in asset.properties:
        business_criticality = _get_property_val(asset.properties["business_criticality"]).upper()

    # Iterate properties, finding cryptographic algorithms
    # Typical Phase 3 canonical properties might be:
    # "crypto:tls:kex": "ECDHE"
    # "crypto:tls:enc": "AES-256"
    # "crypto:sast:algorithm": "RSA"
    for prop_name, prop_val in asset.properties.items():
        if not prop_name.startswith("crypto:"):
            continue
            
        algorithm = _get_property_val(prop_val)
        is_kex = "kex" in prop_name.lower() or "key_exchange" in prop_name.lower()
        
        evidence = [f"Derived from canonical property '{prop_name}'"]
        if isinstance(prop_val, CanonicalProperty):
            evidence.append(f"Confidence: {prop_val.confidence}")

        assessment = assess_quantum_risk(
            asset_id=asset.asset_id,
            algorithm_name=algorithm,
            key_exchange_role=is_kex,
            timeline=timeline,
            data_sensitivity=sensitivity,
            business_criticality=business_criticality,
            migration_complexity="MEDIUM",  # Could be derived
            evidence=evidence
        )
        assessments.append(assessment)

    return assessments
