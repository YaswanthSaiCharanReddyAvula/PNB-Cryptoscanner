"""
Phase 4 — HNDL Assessment Engine

Evaluates Harvest Now, Decrypt Later (HNDL) exposure by combining:
- Cryptographic key exchange vulnerability (Shor vulnerability)
- Data Sensitivity
- Data Lifetime (Tc)
"""

from typing import Dict
from app.scanner.quantum.models import QuantumTimeline, HNDLAssessment

# Simple configurable weighting for Data Sensitivity
SENSITIVITY_WEIGHT: Dict[str, float] = {
    "PUBLIC": 0.0,
    "INTERNAL": 0.3,
    "CONFIDENTIAL": 0.7,
    "SENSITIVE": 0.85,
    "HIGHLY_SENSITIVE": 1.0,
    "LONG_TERM_SECRET": 1.0,
    "UNKNOWN": 0.5
}

def calculate_hndl_exposure(
    is_vulnerable_kex: bool,
    data_sensitivity: str,
    timeline: QuantumTimeline
) -> HNDLAssessment:
    """
    HNDL Exposure = Key Exchange Vulnerability * Data Sensitivity * Data Lifetime Factor
    """
    if not is_vulnerable_kex:
        return HNDLAssessment(
            vulnerable_crypto=False,
            key_exchange_exposure=False,
            data_sensitivity=data_sensitivity,
            exposure=0.0,
            weight=1.0
        )
        
    sensitivity_val = SENSITIVITY_WEIGHT.get(data_sensitivity.upper(), 0.5)
    
    # Exposure is derived directly from data sensitivity. 
    # Temporal factors (like Tc) are handled by Mosca to avoid double-counting.
    exposure = sensitivity_val
    
    # Base weight multiplier applied to the overall risk based on HNDL exposure
    # An exposure of 1.0 yields a 1.5x multiplier. 
    # An exposure of 0.0 yields a 1.0x multiplier.
    weight = 1.0 + (0.5 * exposure)
    
    return HNDLAssessment(
        vulnerable_crypto=True,
        key_exchange_exposure=True,
        data_sensitivity=data_sensitivity,
        exposure=round(exposure * 100, 2),  # 0 to 100 scale
        weight=round(weight, 2)
    )
