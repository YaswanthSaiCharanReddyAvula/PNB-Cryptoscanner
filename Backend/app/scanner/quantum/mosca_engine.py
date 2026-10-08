"""
Phase 4 — Mosca Engine

Calculates the Mosca Margin (Tm + Tc - Tq) and determines migration urgency.
"""

from typing import Tuple, Literal
from app.scanner.quantum.models import QuantumTimeline, MoscaAssessment

def calculate_mosca_assessment(timeline: QuantumTimeline) -> MoscaAssessment:
    """
    Mosca Margin = Tm + Tc - Tq
    """
    # If any required time value is missing, we cannot properly compute the margin.
    if timeline.Tm.value is None or timeline.Tc.value is None or timeline.Tq.value is None:
        return MoscaAssessment(
            margin=None,
            status="INSUFFICIENT_DATA"
        )
        
    margin = timeline.Tm.value + timeline.Tc.value - timeline.Tq.value
    
    # Status determination based on margin
    if margin < -2:
        status = "SAFE_MARGIN"
    elif margin < 0:
        status = "BORDERLINE"
    elif margin == 0:
        status = "MIGRATION_REQUIRED"
    elif margin > 0:
        status = "CRITICAL_URGENCY"
    else:
        status = "NOT_APPLICABLE"
        
    return MoscaAssessment(
        margin=margin,
        status=status
    )
