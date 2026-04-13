"""
QuantumShield — Quantum Risk Engine

Evaluates cryptographic components against PQC transition heuristics (see
NIST IR 8547 for organizational framing; this module is observational, not a
formal certification).

Scoring (v2)
------------
1. Each `CryptoComponent` maps to a 0–100 sub-score using the versioned
   catalog in ``data/pqc_algorithm_catalog.json`` (see ``quantum_catalog``).
2. Per category, the **minimum** sub-score is used (weakest link).
3. Weighted mean of category minima:
   - key_exchange: 36%, signature: 28%, cipher: 18%, protocol: 8%, hash: 10%
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Literal, Optional, Tuple

from app.db.models import (
    AlgorithmCategory,
    CryptoComponent,
    QuantumScore,
    QuantumScoreBreakdown,
    RiskLevel,
)
from app.modules import quantum_catalog
from app.utils.logger import get_logger

logger = get_logger(__name__)

AggregationMode = Literal["estate_weakest", "per_host_min", "p25"]

# Weights — include HASH (plan Phase 1); sum = 1.0
CATEGORY_WEIGHTS: Dict[AlgorithmCategory, float] = {
    AlgorithmCategory.KEY_EXCHANGE: 0.36,
    AlgorithmCategory.SIGNATURE: 0.28,
    AlgorithmCategory.CIPHER: 0.18,
    AlgorithmCategory.PROTOCOL: 0.08,
    AlgorithmCategory.HASH: 0.10,
}


def _cipher_quantum_score(bits: int | None) -> float:
    if bits is None:
        return 50.0
    if bits >= 256:
        return 95.0
    if bits >= 192:
        return 80.0
    if bits >= 128:
        return 60.0
    return 20.0


def _score_component_detail(component: CryptoComponent) -> Tuple[float, str]:
    """Return (score 0–100, short driver label)."""
    name = component.name or ""

    match component.category:
        case AlgorithmCategory.KEY_EXCHANGE:
            return quantum_catalog.score_key_exchange(name)

        case AlgorithmCategory.SIGNATURE:
            return quantum_catalog.score_signature(name, component.key_size)

        case AlgorithmCategory.CIPHER:
            b = component.key_size
            sc = _cipher_quantum_score(b)
            return sc, f"Cipher effective bits (Grover margin): {b or 'unknown'}"

        case AlgorithmCategory.PROTOCOL:
            sc, lab = quantum_catalog.protocol_score(name)
            return sc, lab

        case AlgorithmCategory.HASH:
            return quantum_catalog.score_hash(name)

        case _:
            return 50.0, f"Other: {name[:40]}"


def _category_mins(
    components: List[CryptoComponent],
) -> Tuple[Dict[AlgorithmCategory, float], Dict[AlgorithmCategory, str]]:
    """Weakest score per category + label for that minimum."""
    buckets: Dict[AlgorithmCategory, List[Tuple[float, str]]] = defaultdict(list)
    for comp in components:
        sc, label = _score_component_detail(comp)
        buckets[comp.category].append((sc, label))

    mins: Dict[AlgorithmCategory, float] = {}
    labels: Dict[AlgorithmCategory, str] = {}
    for cat, pairs in buckets.items():
        best_pair = min(pairs, key=lambda x: x[0])
        mins[cat] = best_pair[0]
        labels[cat] = best_pair[1]
    return mins, labels


def _risk_level_from_score(score: float) -> RiskLevel:
    if score >= 80:
        return RiskLevel.SAFE
    if score >= 60:
        return RiskLevel.LOW
    if score >= 40:
        return RiskLevel.MEDIUM
    if score >= 20:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _top_negative_drivers(
    category_min: Dict[AlgorithmCategory, float],
    cat_labels: Dict[AlgorithmCategory, str],
    limit: int = 3,
) -> List[str]:
    """Lowest category scores first — audit-friendly."""
    ranked = sorted(category_min.items(), key=lambda x: x[1])
    out: List[str] = []
    for cat, sc in ranked[:limit]:
        lab = cat_labels.get(cat, cat.value)
        out.append(f"{cat.value} ({sc:.0f}/100): {lab}")
    return out


def _summary_text(final_score: float, breakdown: QuantumScoreBreakdown) -> str:
    parts: List[str] = []
    if breakdown.key_exchange_score < 40:
        parts.append("Key exchange is quantum-vulnerable (consider ML-KEM / hybrid TLS)")
    if breakdown.signature_score < 40:
        parts.append("Signature algorithm is quantum-vulnerable (consider ML-DSA / SLH-DSA)")
    if breakdown.cipher_score < 60:
        parts.append("Cipher key size may be insufficient post-quantum (prefer AES-256)")
    if breakdown.hash_score < 50:
        parts.append("Weak hash in chain or cert (move off SHA-1/MD5)")
    if not parts:
        parts.append("Cryptographic posture shows reasonable quantum readiness")
    return "; ".join(parts) + f". Overall score: {final_score}/100."


def _confidence_from_tls_levels(levels: Optional[List[float]]) -> float:
    if not levels:
        return 0.65
    v = min(float(x) for x in levels if x is not None)
    return max(0.2, min(1.0, v))


def _compute_single(components: List[CryptoComponent]) -> Tuple[float, QuantumScoreBreakdown, Dict[AlgorithmCategory, str]]:
    category_min, cat_labels = _category_mins(components)
    present = {c.category for c in components}

    bd = QuantumScoreBreakdown(
        key_exchange_score=category_min.get(AlgorithmCategory.KEY_EXCHANGE, 0.0),
        signature_score=category_min.get(AlgorithmCategory.SIGNATURE, 0.0),
        cipher_score=(
            category_min[AlgorithmCategory.CIPHER]
            if AlgorithmCategory.CIPHER in category_min
            else 50.0
        ),
        protocol_score=(
            category_min[AlgorithmCategory.PROTOCOL]
            if AlgorithmCategory.PROTOCOL in category_min
            else 50.0
        ),
        hash_score=(
            category_min[AlgorithmCategory.HASH]
            if AlgorithmCategory.HASH in category_min
            else 50.0
        ),
    )

    # Weighted mean only over categories observed in this component list
    weighted = 0.0
    total_w = 0.0
    for cat, w in CATEGORY_WEIGHTS.items():
        if cat not in present:
            continue
        if cat not in category_min:
            continue
        weighted += category_min[cat] * w
        total_w += w
    if total_w <= 0:
        fs = 0.0
    else:
        fs = round(weighted / total_w, 1)

    # Driver labels: merge neutral display for absent categories
    disp_labels = dict(cat_labels)
    if AlgorithmCategory.CIPHER not in category_min:
        disp_labels[AlgorithmCategory.CIPHER] = "No cipher in subset (display 50)"
    if AlgorithmCategory.PROTOCOL not in category_min:
        disp_labels[AlgorithmCategory.PROTOCOL] = "No protocol in subset (display 50)"
    if AlgorithmCategory.HASH not in category_min:
        disp_labels[AlgorithmCategory.HASH] = "No hash in subset (display 50)"

    return fs, bd, disp_labels


def calculate_score(
    components: List[CryptoComponent],
    *,
    aggregation: AggregationMode = "estate_weakest",
    tls_scan_confidences: Optional[List[float]] = None,
) -> QuantumScore:
    """
    Aggregate Quantum Readiness Score.

    ``aggregation``:
      - ``estate_weakest``: one pool of components (legacy behaviour).
      - ``per_host_min``: score each ``host`` separately, then take the **minimum**
        host score (worst endpoint).
      - ``p25``: 25th percentile of per-host scores (less pessimistic rollup).
    """
    catalog_version = quantum_catalog.get_catalog_version()
    confidence = _confidence_from_tls_levels(tls_scan_confidences)

    if not components:
        return QuantumScore(
            score=0.0,
            risk_level=RiskLevel.CRITICAL,
            breakdown=QuantumScoreBreakdown(),
            summary="No cryptographic components found — unable to assess.",
            confidence=max(0.3, confidence * 0.85),
            catalog_version=catalog_version,
            drivers=["No CBOM components to score"],
            aggregation=aggregation,
        )

    def package(fs: float, bd: QuantumScoreBreakdown, cat_labels: Dict[AlgorithmCategory, str]) -> QuantumScore:
        risk = _risk_level_from_score(fs)
        drivers = _top_negative_drivers(
            {
                AlgorithmCategory.KEY_EXCHANGE: bd.key_exchange_score,
                AlgorithmCategory.SIGNATURE: bd.signature_score,
                AlgorithmCategory.CIPHER: bd.cipher_score,
                AlgorithmCategory.PROTOCOL: bd.protocol_score,
                AlgorithmCategory.HASH: bd.hash_score,
            },
            cat_labels,
            3,
        )
        return QuantumScore(
            score=fs,
            risk_level=risk,
            breakdown=bd,
            summary=_summary_text(fs, bd),
            confidence=confidence,
            catalog_version=catalog_version,
            drivers=drivers,
            aggregation=aggregation,
        )

    if aggregation == "estate_weakest":
        fs, bd, cat_labels = _compute_single(components)
        out = package(fs, bd, cat_labels)
        logger.info("Quantum score calculated: %.1f (%s)", fs, out.risk_level.value)
        return out

    # Per-host groupings
    by_host: Dict[str, List[CryptoComponent]] = defaultdict(list)
    for c in components:
        h = (c.host or "").strip() or "_unknown_"
        by_host[h].append(c)

    host_rows: List[Tuple[float, QuantumScoreBreakdown, Dict[AlgorithmCategory, str]]] = []
    for _h, comps in by_host.items():
        fs, bd, labels = _compute_single(comps)
        host_rows.append((fs, bd, labels))

    if not host_rows:
        return package(0.0, QuantumScoreBreakdown(), {})

    host_rows.sort(key=lambda x: x[0])
    if aggregation == "per_host_min":
        fs, bd, labels = host_rows[0]
    else:  # p25
        n = len(host_rows)
        idx = max(0, min(n - 1, int(0.25 * (n - 1))))
        fs, bd, labels = host_rows[idx]

    out = package(fs, bd, labels)
    logger.info(
        "Quantum score (%s, n_hosts=%d): %.1f (%s)",
        aggregation,
        len(by_host),
        fs,
        out.risk_level.value,
    )
    return out


# Legacy table kept for tests / imports that referenced module-level names
KX_SCORES = {
    "RSA": 10,
    "DH": 15,
    "DHE": 20,
    "ECDH": 20,
    "ECDHE": 25,
    "KYBER": 95,
    "CRYSTALS-KYBER": 95,
}

SIG_SCORE_RULES = [
    ("dilithium", 95),
    ("falcon", 90),
    ("sphincs", 85),
    ("ed25519", 30),
    ("ed448", 30),
    ("ecdsa", 25),
    ("rsa", 15),
    ("dsa", 10),
    ("md5", 5),
    ("sha1", 5),
]

PROTOCOL_SCORES = {
    "TLSv1.3": 90,
    "TLSv1.2": 70,
    "TLSv1.1": 30,
    "TLSv1": 20,
    "SSLv3": 5,
    "SSLv2": 0,
}
