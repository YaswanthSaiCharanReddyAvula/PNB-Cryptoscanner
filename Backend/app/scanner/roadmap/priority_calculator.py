"""
Phase 5 — Priority Calculator

Replaces static priority sorting with a contextual priority engine.
Calculates deterministic priority scores and determines the Priority Tier.
"""

from typing import Dict, Any
from app.scanner.roadmap.models import PriorityDrivers, PriorityTier

def calculate_priority_score(drivers: PriorityDrivers) -> float:
    """
    Computes an aggregated priority score (0-100) from independent dimensions.
    Weights are applied to contextual drivers.
    """
    # 1. Base Risks (Max of Classical or Quantum)
    # If a system is classically critical, it needs immediate fix.
    # If it is quantum critical, it needs immediate fix.
    base_risk = max(drivers.classical_risk, drivers.quantum_risk)
    
    # 2. Exposure Multipliers
    # Internet-facing assets carry higher risk.
    exposure_multiplier = 1.0
    if drivers.exposure > 0:
        exposure_multiplier = 1.2 # Up to 20% increase for internet exposure
        
    # 3. Criticality Multipliers
    criticality_multiplier = 1.0
    if drivers.criticality > 0:
        criticality_multiplier = 1.0 + (drivers.criticality * 0.3) # Up to 30% increase for business critical assets
        
    # 4. HNDL and Mosca Urgency
    # HNDL indicates data is currently at risk of capture.
    hndl_adder = drivers.hndl * 10.0 # Add up to 10 points
    
    # Mosca urgency means time is running out.
    mosca_adder = drivers.mosca_urgency * 15.0 # Add up to 15 points
    
    # 5. Dependency Impact
    # If this task blocks many others, it should be prioritized.
    dependency_adder = drivers.dependency_impact * 5.0
    
    # Calculate unconstrained score
    raw_score = (base_risk * exposure_multiplier * criticality_multiplier) + hndl_adder + mosca_adder + dependency_adder
    
    # 6. Confidence Penalty
    # If we are unsure (low confidence), reduce the priority slightly so confirmed issues surface first.
    # A confidence of 1.0 means no penalty. 0.5 means a 10% penalty.
    confidence_penalty = (1.0 - drivers.confidence) * 0.2
    raw_score = raw_score * (1.0 - confidence_penalty)
    
    # Cap at 100
    final_score = min(max(raw_score, 0.0), 100.0)
    
    return round(final_score, 2)


def determine_tier(score: float, mosca_status: str = "UNKNOWN") -> PriorityTier:
    """
    Maps the computed score to a PriorityTier.
    Backend owns this semantic definition.
    """
    # Explicit overrides for extreme urgency
    if mosca_status == "CRITICAL_URGENCY":
        return PriorityTier.CRITICAL
        
    if score >= 90.0:
        return PriorityTier.CRITICAL
    elif score >= 70.0:
        return PriorityTier.HIGH
    elif score >= 40.0:
        return PriorityTier.MEDIUM
    elif score >= 10.0:
        return PriorityTier.LOW
    else:
        return PriorityTier.LOW # Safe/informational tasks go to LOW for tracking

def map_criticality(val: str) -> float:
    mapping = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.2,
        "UNKNOWN": 0.0
    }
    return mapping.get(val.upper(), 0.0)

def map_exposure(val: str) -> float:
    mapping = {
        "INTERNET_FACING": 1.0,
        "EXTERNAL": 0.8,
        "INTERNAL": 0.2,
        "ISOLATED": 0.0,
        "UNKNOWN": 0.0
    }
    return mapping.get(val.upper(), 0.0)
