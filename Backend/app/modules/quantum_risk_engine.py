"""
QuantumShield — Quantum Risk Engine

Evaluates a set of cryptographic components against post-quantum
cryptography (PQC) standards and computes a Quantum Readiness
Score from 0 (fully vulnerable) to 100 (quantum-safe).

Scoring formula (documented for audits)
---------------------------------------
1. Each `CryptoComponent` is mapped to a 0–100 sub-score by category
   (key exchange, signature, cipher, protocol).
2. For each category present in the scan, the **minimum** sub-score
   is taken (weakest link within that category).
3. The final score is a **weighted mean** of those category minima:
   - key_exchange: 40%
   - signature:    30%
   - cipher:       20%
   - protocol:     10%

Optional tuning via env is not implemented; weights are fixed in
`CATEGORY_WEIGHTS` below.
"""

from typing import List

from app.db.models import (
    AlgorithmCategory,
    CryptoComponent,
    QuantumScore,
    QuantumScoreBreakdown,
    QuantumStatus,
    RiskLevel,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Weights —  how much each category contributes to the final score ──
CATEGORY_WEIGHTS = {
    AlgorithmCategory.KEY_EXCHANGE: 0.40,
    AlgorithmCategory.SIGNATURE:   0.30,
    AlgorithmCategory.CIPHER:      0.20,
    AlgorithmCategory.PROTOCOL:    0.10,
}

# ── Per-component quantum score mapping ──────────────────────────

# Key-exchange quantum scores
KX_SCORES = {
    # Quantum-vulnerable key exchanges
    "RSA":    10,
    "DH":     15,
    "DHE":    20,
    "ECDH":   20,
    "ECDHE":  25,
    # Post-quantum
    "KYBER":  95,
    "CRYSTALS-KYBER": 95,
}

# Signature algorithm quantum scores (substring matching)
SIG_SCORE_RULES = [
    # (substring, score)
    ("dilithium",  95),
    ("falcon",     90),
    ("sphincs",    85),
    ("ed25519",    30),
    ("ed448",      30),
    ("ecdsa",      25),
    ("rsa",        15),
    ("dsa",        10),
    ("md5",         5),
    ("sha1",        5),
]

# Cipher suite quantum scores (based on key size resilience to Grover's)
def _cipher_quantum_score(bits: int | None) -> float:
    """
    Symmetric ciphers are affected by Grover's algorithm,
    which halves the effective key size.
    AES-256 → 128-bit post-quantum   → safe
    AES-128 → 64-bit  post-quantum   → marginal
    """
    if bits is None:
        return 50  # unknown
    if bits >= 256:
        return 95
    if bits >= 192:
        return 80
    if bits >= 128:
        return 60
    return 20  # <128-bit ciphers are weak even classically

# Protocol version quantum scores
PROTOCOL_SCORES = {
    "TLSv1.3": 90,
    "TLSv1.2": 70,
    "TLSv1.1": 30,
    "TLSv1":   20,
    "SSLv3":    5,
    "SSLv2":    0,
}


def _score_component(component: CryptoComponent) -> float:
    """Score a single component on a 0-100 quantum-readiness scale."""
    name = (component.name or "").upper()
    name_lower = (component.name or "").lower().replace("-", "").replace("_", "")

    match component.category:
        case AlgorithmCategory.KEY_EXCHANGE:
            if any(
                k in name_lower
                for k in ("kyber", "mlkem", "crystals", "pqtls", "kemtls")
            ):
                return 95
            return KX_SCORES.get(name, 30)

        case AlgorithmCategory.SIGNATURE:
            for substr, score in SIG_SCORE_RULES:
                if substr in name_lower:
                    return score
            return 30  # unknown signature algorithm

        case AlgorithmCategory.CIPHER:
            return _cipher_quantum_score(component.key_size)

        case AlgorithmCategory.PROTOCOL:
            return PROTOCOL_SCORES.get(component.name, 40)

        case _:
            return 50


def _risk_level_from_score(score: float) -> RiskLevel:
    """Map numeric score to a human-readable risk level."""
    if score >= 80:
        return RiskLevel.SAFE
    if score >= 60:
        return RiskLevel.LOW
    if score >= 40:
        return RiskLevel.MEDIUM
    if score >= 20:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def calculate_score(components: List[CryptoComponent]) -> QuantumScore:
    """
    Compute the aggregate Quantum Readiness Score.

    Strategy:
      1. Group components by category.
      2. Score each component individually.
      3. For each category, take the *minimum* score (weakest link).
      4. Apply category weights to get the final weighted score.

    Returns:
        QuantumScore with breakdown and risk level.
    """
    if not components:
        return QuantumScore(
            score=0,
            risk_level=RiskLevel.CRITICAL,
            breakdown=QuantumScoreBreakdown(),
            summary="No cryptographic components found — unable to assess.",
        )

    # Group components by category
    category_scores: dict[AlgorithmCategory, list[float]] = {}
    for comp in components:
        s = _score_component(comp)
        category_scores.setdefault(comp.category, []).append(s)

    # Weakest-link per category (minimum score)
    category_min: dict[AlgorithmCategory, float] = {
        cat: min(scores) for cat, scores in category_scores.items()
    }

    breakdown = QuantumScoreBreakdown(
        key_exchange_score=category_min.get(AlgorithmCategory.KEY_EXCHANGE, 0),
        signature_score=category_min.get(AlgorithmCategory.SIGNATURE, 0),
        cipher_score=category_min.get(AlgorithmCategory.CIPHER, 50),
        protocol_score=category_min.get(AlgorithmCategory.PROTOCOL, 50),
    )

    # Weighted aggregate
    weighted = 0.0
    total_weight = 0.0
    for cat, weight in CATEGORY_WEIGHTS.items():
        if cat in category_min:
            weighted += category_min[cat] * weight
            total_weight += weight

    final_score = round(weighted / total_weight, 1) if total_weight > 0 else 0
    risk = _risk_level_from_score(final_score)

    summary_parts = []
    if breakdown.key_exchange_score < 40:
        summary_parts.append("Key exchange is quantum-vulnerable (consider CRYSTALS-Kyber)")
    if breakdown.signature_score < 40:
        summary_parts.append("Signature algorithm is quantum-vulnerable (consider Dilithium/Falcon)")
    if breakdown.cipher_score < 60:
        summary_parts.append("Cipher key size may be insufficient post-quantum (use AES-256)")
    if not summary_parts:
        summary_parts.append("Cryptographic posture shows reasonable quantum readiness")

    summary = "; ".join(summary_parts) + f". Overall score: {final_score}/100."

    logger.info("Quantum score calculated: %.1f (%s)", final_score, risk.value)
    return QuantumScore(
        score=final_score,
        risk_level=risk,
        breakdown=breakdown,
        summary=summary,
    )
