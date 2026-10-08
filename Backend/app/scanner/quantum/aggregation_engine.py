from typing import List, Dict
from app.scanner.quantum.models import (
    QuantumRiskAssessment,
    AssetQuantumRiskSummary,
    ApplicationQuantumRiskSummary,
    OrganizationQuantumRiskSummary,
    HNDLSummary,
    MoscaSummary
)

def aggregate_asset_risk(asset_id: str, assessments: List[QuantumRiskAssessment]) -> AssetQuantumRiskSummary:
    if not assessments:
        return AssetQuantumRiskSummary(
            asset_id=asset_id,
            quantum_risk_score=0.0,
            risk_tier="UNKNOWN",
            hndl=HNDLSummary(exposure=0.0, classification="UNKNOWN"),
            mosca=MoscaSummary(status="NOT_APPLICABLE"),
            migration_priority="UNKNOWN",
            confidence=0.0,
            unknown_coverage=1.0,
            assessments=[]
        )

    # Maximum credible exposure weighting (for simplicity, we use the max score)
    # as quantum risk is driven by the weakest link (highest risk score)
    max_risk = 0.0
    max_hndl_exposure = 0.0
    highest_hndl_class = "SAFE"
    most_urgent_mosca = "SAFE_MARGIN"
    highest_priority = "MONITOR"
    min_confidence = 1.0
    
    unknown_count = 0
    total_count = len(assessments)
    
    PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "MONITOR": 4, "UNKNOWN": 5, "NONE": 6}
    MOSCA_ORDER = {"CRITICAL_URGENCY": 0, "MIGRATION_REQUIRED": 1, "BORDERLINE": 2, "SAFE_MARGIN": 3, "NOT_APPLICABLE": 4, "INSUFFICIENT_DATA": 5}
    TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4, "UNKNOWN": 5}
    
    worst_tier = "SAFE"
    
    for a in assessments:
        if a.risk_tier == "UNKNOWN":
            unknown_count += 1
        
        max_risk = max(max_risk, a.overall_quantum_risk)
        max_hndl_exposure = max(max_hndl_exposure, a.hndl.exposure)
        
        if TIER_ORDER.get(a.risk_tier, 5) < TIER_ORDER.get(worst_tier, 5):
            worst_tier = a.risk_tier
            
        if PRIORITY_ORDER.get(a.migration_priority, 6) < PRIORITY_ORDER.get(highest_priority, 6):
            highest_priority = a.migration_priority
            
        if MOSCA_ORDER.get(a.mosca.status, 5) < MOSCA_ORDER.get(most_urgent_mosca, 5):
            most_urgent_mosca = a.mosca.status
            
        min_confidence = min(min_confidence, a.confidence)

    # HNDL Classification
    hndl_class = "SAFE"
    if max_hndl_exposure >= 75:
        hndl_class = "CRITICAL"
    elif max_hndl_exposure >= 50:
        hndl_class = "HIGH"
    elif max_hndl_exposure >= 25:
        hndl_class = "MEDIUM"
    elif max_hndl_exposure > 0:
        hndl_class = "LOW"
        
    return AssetQuantumRiskSummary(
        asset_id=asset_id,
        quantum_risk_score=max_risk,
        risk_tier=worst_tier,
        hndl=HNDLSummary(exposure=max_hndl_exposure, classification=hndl_class),
        mosca=MoscaSummary(status=most_urgent_mosca),
        migration_priority=highest_priority,
        confidence=min_confidence,
        unknown_coverage=unknown_count / total_count,
        assessments=assessments
    )

def aggregate_organization_risk(asset_summaries: List[AssetQuantumRiskSummary]) -> OrganizationQuantumRiskSummary:
    if not asset_summaries:
        return OrganizationQuantumRiskSummary(
            overall_quantum_risk_score=0.0,
            risk_tier="UNKNOWN",
            total_assets=0,
            critical_assets=0,
            p0_assets=0,
            hndl_exposed_assets=0,
            mosca_boundary_assets=0,
            unknown_crypto_assets=0,
            pqc_ready_assets=0,
            known_coverage=0.0,
            unknown_coverage=1.0,
            confidence=0.0
        )
        
    total_assets = len(asset_summaries)
    critical_assets = 0
    p0_assets = 0
    hndl_exposed = 0
    mosca_boundary = 0
    unknown_crypto = 0
    pqc_ready = 0
    
    max_risk = 0.0
    total_confidence = 0.0
    total_unknown_coverage = 0.0
    
    for s in asset_summaries:
        max_risk = max(max_risk, s.quantum_risk_score)
        total_confidence += s.confidence
        total_unknown_coverage += s.unknown_coverage
        
        if s.risk_tier == "CRITICAL":
            critical_assets += 1
        if s.migration_priority == "P0":
            p0_assets += 1
        if s.hndl.classification in ("CRITICAL", "HIGH"):
            hndl_exposed += 1
        if s.mosca.status in ("CRITICAL_URGENCY", "MIGRATION_REQUIRED", "BORDERLINE"):
            mosca_boundary += 1
        if s.unknown_coverage > 0:
            unknown_crypto += 1
        if s.risk_tier == "SAFE" and s.unknown_coverage == 0:
            pqc_ready += 1

    TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4, "UNKNOWN": 5}
    worst_tier = "SAFE"
    for s in asset_summaries:
        if TIER_ORDER.get(s.risk_tier, 5) < TIER_ORDER.get(worst_tier, 5):
            worst_tier = s.risk_tier

    avg_unknown_coverage = total_unknown_coverage / total_assets
    
    return OrganizationQuantumRiskSummary(
        overall_quantum_risk_score=max_risk,
        risk_tier=worst_tier,
        total_assets=total_assets,
        critical_assets=critical_assets,
        p0_assets=p0_assets,
        hndl_exposed_assets=hndl_exposed,
        mosca_boundary_assets=mosca_boundary,
        unknown_crypto_assets=unknown_crypto,
        pqc_ready_assets=pqc_ready,
        known_coverage=1.0 - avg_unknown_coverage,
        unknown_coverage=avg_unknown_coverage,
        confidence=total_confidence / total_assets
    )
