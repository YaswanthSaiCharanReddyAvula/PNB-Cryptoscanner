"""
QuantumShield — Recommendation Engine

Maps each quantum-vulnerable cryptographic component to its
recommended post-quantum replacement, with migration guidance.
"""

from typing import List

from app.db.models import (
    AlgorithmCategory,
    CryptoComponent,
    QuantumScore,
    QuantumStatus,
    Recommendation,
    RiskLevel,
)
from app.utils.logger import get_logger
from app.scanner.roadmap.adapters.phase3_adapter import NormalizedFindingContext
from app.scanner.roadmap.decision_engine import PqcDecisionEngine

logger = get_logger(__name__)

def get_recommendations(
    components: List[CryptoComponent],
    quantum_score: QuantumScore,
) -> List[Recommendation]:
    """
    Generate PQC migration recommendations for all vulnerable components.

    Delegates to the authoritative PqcDecisionEngine via an adapter layer.

    Args:
        components:    CBOM components from the crypto analyser.
        quantum_score: Overall quantum readiness score.

    Returns:
        Prioritised list of Recommendation objects.
    """
    recommendations: List[Recommendation] = []

    for comp in components:
        if comp.quantum_status == QuantumStatus.QUANTUM_SAFE:
            continue  # no action needed

        rec = _build_recommendation(comp)
        if rec:
            recommendations.append(rec)

    # Sort by priority: CRITICAL → HIGH → MEDIUM → LOW → SAFE
    priority_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.SAFE: 4,
    }
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 5))

    logger.info(
        "Generated %d recommendations (quantum score: %.1f)",
        len(recommendations),
        quantum_score.score,
    )
    return recommendations


def _build_recommendation(comp: CryptoComponent) -> Recommendation | None:
    """Build a single recommendation by delegating to PqcDecisionEngine."""
    
    finding = NormalizedFindingContext(
        finding_id=f"legacy-{comp.name}",
        finding_type=f"{comp.name} {comp.category.value if hasattr(comp.category, 'value') else str(comp.category)}",
        severity=comp.risk_level.value if hasattr(comp.risk_level, 'value') else str(comp.risk_level),
        confidence=1.0,
        state="OBSERVED",
        details={
            "algorithm": comp.name,
            "primitive": comp.category.value if hasattr(comp.category, 'value') else str(comp.category),
        }
    )
    
    pqc_rec = PqcDecisionEngine.generate_recommendation(finding, [])
    
    if pqc_rec.recommended_candidate:
        rationale = f"Trade-off winner: {pqc_rec.recommended_candidate}."
        if pqc_rec.alternative_candidates:
            rationale += f" Alternatives considered: {', '.join(pqc_rec.alternative_candidates)}."
        
        return Recommendation(
            current_algorithm=comp.name,
            recommended_algorithm=pqc_rec.recommended_candidate,
            category=comp.category,
            priority=comp.risk_level,
            rationale=rationale,
            migration_notes="Prerequisites: " + ", ".join(pqc_rec.required_prerequisites),
        )

    # Fallback generic recommendation for quantum-vulnerable components
    if comp.quantum_status == QuantumStatus.VULNERABLE:
        return Recommendation(
            current_algorithm=comp.name,
            recommended_algorithm="Evaluate PQC alternative (see NIST PQC standards)",
            category=comp.category,
            priority=comp.risk_level,
            rationale=f"{comp.name} is classified as quantum-vulnerable. Engine limitations: {', '.join(pqc_rec.limitations)}",
            migration_notes="Consult NIST SP 800-208 and the PQC migration guide.",
        )

    return None
