"""
TLS modern vs post-quantum KEM hints.

Negotiated cipher / KEX names sometimes advertise hybrid schemes (e.g. X25519Kyber768).
We never infer true library-level PQC deployment — only string signals from scan output.
"""

from __future__ import annotations

import re
from typing import Any, List

from app.db.models import TLSInfo

# Negotiated or offered cipher/KEX names suggesting hybrid / PQ KEM (order: longer first)
_PQC_KEM_PATTERNS: tuple[str, ...] = (
    "X25519KYBER768",
    "X25519_KYBER768",
    "SECP256R1KYBER768",
    "ECDHEKYBER",
    "CRYSTALSKYBER",
    "CRYSTALS-KYBER",
    "ML-KEM",
    "MLKEM",
    "ML_KEM",
    "KYBER768",
    "KYBER512",
    "KYBER1024",
    "KYBER",
    "PQTLS",
    "KEMTLS",
)


def _norm_alnum(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", s.upper())


def _cipher_blob(
    cipher_suite: str | None,
    key_exchange: str | None,
    all_supported_ciphers: List[dict[str, Any]],
) -> str:
    parts: List[str] = [cipher_suite or "", key_exchange or ""]
    for c in all_supported_ciphers:
        if isinstance(c, dict):
            parts.append(str(c.get("name") or ""))
    return " ".join(parts)


def detect_pqc_signals(
    tls_version: str | None,
    cipher_suite: str | None,
    key_exchange: str | None,
    all_supported_ciphers: List[dict[str, Any]],
) -> dict[str, Any]:
    """Return flags + matched hint strings for audit."""
    blob_raw = _cipher_blob(cipher_suite, key_exchange, all_supported_ciphers)
    blob = _norm_alnum(blob_raw)

    raw_hints: List[str] = []
    for pat in _PQC_KEM_PATTERNS:
        pn = _norm_alnum(pat)
        if len(pn) >= 4 and pn in blob:
            raw_hints.append(pat)

    # One primary label: longest pattern matched (most specific signal).
    minimal: List[str] = []
    if raw_hints:
        best = max(set(raw_hints), key=lambda x: len(_norm_alnum(x)))
        minimal = [best]

    hybrid = len(minimal) > 0
    pqc_kem_observed = hybrid

    tv = (tls_version or "").upper().replace(" ", "")
    tls_modern = "TLSV1.3" in tv or tv.endswith("1.3") or "TLS1.3" in tv

    return {
        "tls_modern": tls_modern,
        "hybrid_key_exchange": hybrid,
        "pqc_kem_observed": pqc_kem_observed,
        "pqc_signal_hints": minimal[:8],
    }


def enrich_tls_info(info: TLSInfo) -> TLSInfo:
    """Attach PQC / TLS-modern signals to a TLS scan row."""
    if info.error:
        return info
    sig = detect_pqc_signals(
        info.tls_version,
        info.cipher_suite,
        info.key_exchange,
        list(info.all_supported_ciphers or []),
    )
    return info.model_copy(update=sig)
