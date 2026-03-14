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

logger = get_logger(__name__)

# ── PQC Migration Mapping ────────────────────────────────────────

_KX_RECOMMENDATIONS = {
    "RSA": {
        "replacement": "CRYSTALS-Kyber (ML-KEM)",
        "rationale": (
            "RSA key exchange is vulnerable to Shor's algorithm on a "
            "cryptographically relevant quantum computer. CRYSTALS-Kyber "
            "(NIST ML-KEM) provides lattice-based key encapsulation with "
            "equivalent security and is a NIST PQC standard."
        ),
        "migration_notes": (
            "Adopt hybrid TLS key exchange (e.g. X25519Kyber768) as an "
            "intermediate step. Major TLS libraries (OpenSSL 3.2+, BoringSSL) "
            "already support hybrid PQ key exchange."
        ),
    },
    "DH": {
        "replacement": "CRYSTALS-Kyber (ML-KEM)",
        "rationale": (
            "Finite-field Diffie-Hellman is vulnerable to Shor's algorithm. "
            "Transition to lattice-based KEM."
        ),
        "migration_notes": "Replace with ML-KEM in TLS 1.3 configuration.",
    },
    "DHE": {
        "replacement": "CRYSTALS-Kyber (ML-KEM)",
        "rationale": (
            "Ephemeral DH provides forward secrecy but remains quantum-"
            "vulnerable. CRYSTALS-Kyber maintains forward secrecy with "
            "quantum resistance."
        ),
        "migration_notes": (
            "Use hybrid key exchange X25519Kyber768Draft00 for gradual migration."
        ),
    },
    "ECDH": {
        "replacement": "CRYSTALS-Kyber (ML-KEM)",
        "rationale": "ECDH relies on the elliptic-curve discrete log problem, broken by Shor's algorithm.",
        "migration_notes": "Switch to ML-KEM or hybrid X25519+Kyber.",
    },
    "ECDHE": {
        "replacement": "CRYSTALS-Kyber (ML-KEM)",
        "rationale": (
            "ECDHE provides excellent classical security and forward secrecy, "
            "but is quantum-vulnerable. Use hybrid PQ+ECDHE for transition."
        ),
        "migration_notes": (
            "Deploy hybrid key exchange first (X25519Kyber768). This preserves "
            "classical security while adding quantum resistance."
        ),
    },
}

_SIG_RECOMMENDATIONS = {
    "rsa": {
        "replacement": "CRYSTALS-Dilithium (ML-DSA), Falcon, or SPHINCS+ (SLH-DSA)",
        "rationale": (
            "RSA signatures are broken by Shor's algorithm. CRYSTALS-Dilithium "
            "(NIST ML-DSA) is the primary NIST PQC signature standard. "
            "Falcon offers smaller signatures for constrained environments. "
            "SPHINCS+ provides a stateless hash-based alternative."
        ),
        "migration_notes": (
            "For TLS certificates, adopt Dilithium-based certificates. "
            "For specialized or constrained systems, consider Falcon or SPHINCS+."
        ),
    },
    "ecdsa": {
        "replacement": "CRYSTALS-Dilithium (ML-DSA), Falcon, or SPHINCS+",
        "rationale": "ECDSA relies on the ECDLP, which is solved efficiently by Shor's algorithm.",
        "migration_notes": "Use hybrid certificates (ECDSA + Dilithium/Falcon) during transition.",
    },
    "dsa": {
        "replacement": "CRYSTALS-Dilithium (ML-DSA) or SPHINCS+",
        "rationale": "DSA is quantum-vulnerable and also deprecated classically. Immediate migration recommended.",
        "migration_notes": "Replace with Dilithium or SPHINCS+ in all signing operations.",
    },
}

_HASH_RECOMMENDATIONS = {
    "md5": {
        "replacement": "SHA-3 (SHA3-256 / SHA3-512)",
        "rationale": (
            "MD5 is cryptographically broken (collision attacks practical since 2004). "
            "Additionally, Grover's algorithm halves hash security. SHA-3 provides "
            "quantum-resilient hashing."
        ),
        "migration_notes": "Immediate replacement required. MD5 is unsuitable for any security purpose.",
    },
    "sha1": {
        "replacement": "SHA-3 or SHA-256/SHA-384",
        "rationale": (
            "SHA-1 is deprecated (practical collision attacks demonstrated). "
            "Post-quantum, Grover's attack further weakens it."
        ),
        "migration_notes": "Replace with SHA-256 minimum; prefer SHA-3 for future-proofing.",
    },
}

_CIPHER_RECOMMENDATIONS = {
    "low_bits": {
        "replacement": "AES-256-GCM",
        "rationale": (
            "Grover's algorithm effectively halves symmetric key strength. "
            "AES-128 becomes 64-bit equivalent post-quantum. AES-256 maintains "
            "128-bit security against quantum adversaries."
        ),
        "migration_notes": (
            "Configure TLS cipher suites to prefer AES-256-GCM. "
            "Disable AES-128 in high-security banking environments."
        ),
    },
}


def get_recommendations(
    components: List[CryptoComponent],
    quantum_score: QuantumScore,
) -> List[Recommendation]:
    """
    Generate PQC migration recommendations for all vulnerable components.

    Each recommendation includes:
      - Current algorithm and its replacement
      - Security rationale
      - Practical migration notes

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
    """Build a single recommendation for a vulnerable component."""
    name_upper = comp.name.upper()
    name_lower = comp.name.lower().replace("-", "").replace("_", "")

    match comp.category:
        case AlgorithmCategory.KEY_EXCHANGE:
            info = _KX_RECOMMENDATIONS.get(name_upper)
            if info:
                return Recommendation(
                    current_algorithm=comp.name,
                    recommended_algorithm=info["replacement"],
                    category=comp.category,
                    priority=comp.risk_level,
                    rationale=info["rationale"],
                    migration_notes=info["migration_notes"],
                )

        case AlgorithmCategory.SIGNATURE:
            for token, info in _SIG_RECOMMENDATIONS.items():
                if token in name_lower:
                    return Recommendation(
                        current_algorithm=comp.name,
                        recommended_algorithm=info["replacement"],
                        category=comp.category,
                        priority=comp.risk_level,
                        rationale=info["rationale"],
                        migration_notes=info["migration_notes"],
                    )

        case AlgorithmCategory.HASH:
            for token, info in _HASH_RECOMMENDATIONS.items():
                if token in name_lower:
                    return Recommendation(
                        current_algorithm=comp.name,
                        recommended_algorithm=info["replacement"],
                        category=comp.category,
                        priority=RiskLevel.CRITICAL,
                        rationale=info["rationale"],
                        migration_notes=info["migration_notes"],
                    )

        case AlgorithmCategory.CIPHER:
            if comp.key_size and comp.key_size < 256:
                info = _CIPHER_RECOMMENDATIONS["low_bits"]
                return Recommendation(
                    current_algorithm=comp.name,
                    recommended_algorithm=info["replacement"],
                    category=comp.category,
                    priority=RiskLevel.MEDIUM,
                    rationale=info["rationale"],
                    migration_notes=info["migration_notes"],
                )

    # Fallback generic recommendation for quantum-vulnerable components
    if comp.quantum_status == QuantumStatus.VULNERABLE:
        return Recommendation(
            current_algorithm=comp.name,
            recommended_algorithm="Evaluate PQC alternative (see NIST PQC standards)",
            category=comp.category,
            priority=comp.risk_level,
            rationale=f"{comp.name} is classified as quantum-vulnerable.",
            migration_notes="Consult NIST SP 800-208 and the PQC migration guide.",
        )

    return None
