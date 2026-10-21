"""
Phase 4 — HNDL Assessment Engine

Evaluates Harvest Now, Decrypt Later (HNDL) exposure by combining:
- Cryptographic key exchange vulnerability (Shor vulnerability)
- Data Sensitivity
- Data Lifetime (Tc)
"""

from typing import Dict, Optional
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
    timeline: Optional[QuantumTimeline] = None
) -> HNDLAssessment:
    """
    HNDL Exposure = Key Exchange Vulnerability * Data Sensitivity * Data Lifetime Factor

    Parameters:
      - is_vulnerable_kex: True if primitive is an asymmetric key exchange susceptible to Shor's algorithm.
      - data_sensitivity: Classification of protected payload (PUBLIC, INTERNAL, CONFIDENTIAL, SENSITIVE, HIGHLY_SENSITIVE, LONG_TERM_SECRET, UNKNOWN).
      - timeline: QuantumTimeline containing:
          * Tc: Confidentiality Lifetime in years (how long the data must remain secret).
          * Tq: Quantum Threat Timeline in years (estimated horizon until CRQC availability).
          * Tm: Migration Time in years (system migration duration; not used directly in HNDL exposure).

    Timeline Modeling:
      - If data is not vulnerable KEX, exposure is 0.0.
      - If data has no confidentiality requirement (Tc <= 0), exposure is 0.0.
      - When Tc >= Tq, data confidentiality outlasts or meets the quantum threat horizon (lifetime factor = 1.0).
      - When 0 < Tc < Tq, lifetime factor scales proportionally as Tc / Tq.
      - When timeline data is missing or incomplete, conservative lifetime factor 1.0 is assumed to prevent
        falsely reporting a vulnerable asset as safe.
    """
    if not is_vulnerable_kex:
        return HNDLAssessment(
            vulnerable_crypto=False,
            key_exchange_exposure=False,
            data_sensitivity=data_sensitivity,
            exposure=0.0,
            weight=1.0
        )
        
    sensitivity_val = SENSITIVITY_WEIGHT.get(data_sensitivity.upper() if data_sensitivity else "UNKNOWN", 0.5)

    # If sensitivity is strictly 0.0 (e.g. PUBLIC), exposure is 0 regardless of timeline
    if sensitivity_val <= 0.0:
        return HNDLAssessment(
            vulnerable_crypto=True,
            key_exchange_exposure=True,
            data_sensitivity=data_sensitivity,
            exposure=0.0,
            weight=1.0
        )

    # Determine Data Lifetime Factor from timeline (Tc vs Tq)
    lifetime_factor = 1.0
    if timeline is not None:
        tc_val = timeline.Tc.value if (timeline.Tc and timeline.Tc.value is not None) else None
        tq_val = timeline.Tq.value if (timeline.Tq and timeline.Tq.value is not None) else None

        if tc_val is not None and tq_val is not None:
            if tc_val <= 0:
                # Data confidentiality expires immediately or is non-existent
                lifetime_factor = 0.0
            elif tq_val <= 0:
                # CRQC horizon is immediate or already passed; any positive Tc is exposed
                lifetime_factor = 1.0
            elif tc_val >= tq_val:
                # Confidentiality requirement outlasts or meets quantum arrival
                lifetime_factor = 1.0
            else:
                # 0 < Tc < Tq: Proportional temporal exposure
                lifetime_factor = tc_val / tq_val
        elif tc_val is not None and tc_val <= 0:
            # Tc is explicitly 0 or negative even if Tq is missing
            lifetime_factor = 0.0
        else:
            # Incomplete timeline (Tc or Tq missing): preserve uncertainty, do not falsely assume safe
            lifetime_factor = 1.0
    else:
        # Missing timeline entirely: preserve uncertainty, do not falsely assume safe
        lifetime_factor = 1.0

    exposure_ratio = sensitivity_val * lifetime_factor
    exposure = round(exposure_ratio * 100, 2)
    weight = round(1.0 + (0.5 * exposure_ratio), 2)

    return HNDLAssessment(
        vulnerable_crypto=True,
        key_exchange_exposure=True,
        data_sensitivity=data_sensitivity,
        exposure=exposure,
        weight=weight
    )
