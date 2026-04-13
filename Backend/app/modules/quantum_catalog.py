"""
Versioned PQC / classical algorithm catalog for quantum readiness heuristics.

Loads JSON from app/modules/data/pqc_algorithm_catalog.json; falls back to
built-in defaults if the file is missing or invalid.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_CATALOG_PATH = Path(__file__).resolve().parent / "data" / "pqc_algorithm_catalog.json"

_BUILTIN: Dict[str, Any] = {
    "catalog_version": "builtin-fallback",
    "kex_contains_rules": [
        {"contains": ["ml-kem", "mlkem", "ml_kem", "kyber", "crystals", "x25519kyber", "pqtls", "kemtls"], "score": 95, "nist_ref": "FIPS 203", "label": "PQC / hybrid KEM"},
        {"contains": ["ecdhe"], "score": 25, "nist_ref": "ECDHE", "label": "ECDHE"},
        {"contains": ["dhe", "edh"], "score": 20, "nist_ref": "DHE", "label": "DHE"},
        {"contains": ["ecdh"], "score": 22, "nist_ref": "ECDH", "label": "ECDH"},
        {"contains": ["_rsa", "rsa_", "rsa-with", "kexrsa"], "score": 10, "nist_ref": "RSA KX", "label": "RSA KX"},
        {"contains": ["rsa"], "score": 12, "nist_ref": "RSA", "label": "RSA"},
        {"contains": ["dh"], "score": 18, "nist_ref": "DH", "label": "DH"},
    ],
    "sig_contains_rules": [
        {"contains": ["ml-dsa", "mldsa", "dilithium"], "score": 95, "nist_ref": "FIPS 204", "label": "ML-DSA"},
        {"contains": ["slh-dsa", "slhdsa", "sphincs"], "score": 88, "nist_ref": "FIPS 205", "label": "SLH-DSA"},
        {"contains": ["falcon"], "score": 90, "nist_ref": "Falcon", "label": "Falcon"},
        {"contains": ["ed25519", "ed448"], "score": 30, "nist_ref": "EdDSA", "label": "EdDSA"},
        {"contains": ["ecdsa"], "score": 25, "nist_ref": "ECDSA", "label": "ECDSA"},
        {"contains": ["dsa"], "score": 12, "nist_ref": "DSA", "label": "DSA"},
        {"contains": ["rsa"], "score": 15, "nist_ref": "RSA", "label": "RSA"},
        {"contains": ["md5"], "score": 5, "nist_ref": "MD5", "label": "MD5"},
        {"contains": ["sha1", "sha-1"], "score": 5, "nist_ref": "SHA-1", "label": "SHA-1"},
    ],
    "rsa_signature_key_size_tiers": [
        {"max_bits": 1023, "score": 5, "label": "RSA <1024"},
        {"max_bits": 2047, "score": 10, "label": "RSA ≤2047"},
        {"max_bits": 3071, "score": 16, "label": "RSA 2048"},
        {"max_bits": 4095, "score": 20, "label": "RSA 3072"},
        {"max_bits": 999999, "score": 24, "label": "RSA ≥4096"},
    ],
    "hash_contains_rules": [
        {"contains": ["md5"], "score": 8, "label": "MD5"},
        {"contains": ["sha-1", "sha1"], "score": 15, "label": "SHA-1"},
        {"contains": ["sha224"], "score": 55, "label": "SHA-224"},
        {"contains": ["sha256"], "score": 78, "label": "SHA-256"},
        {"contains": ["sha384"], "score": 82, "label": "SHA-384"},
        {"contains": ["sha512"], "score": 85, "label": "SHA-512"},
        {"contains": ["sha3"], "score": 88, "label": "SHA-3"},
    ],
    "protocol_scores": {
        "TLSv1.3": 90,
        "TLSv1.2": 70,
        "TLSv1.1": 30,
        "TLSv1": 20,
        "TLSv1.0": 20,
        "SSLv3": 5,
        "SSLv2": 0,
    },
}


def _norm(s: str) -> str:
    return (s or "").lower().replace("-", "").replace("_", "").replace(" ", "")


def load_catalog_dict() -> Dict[str, Any]:
    try:
        raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and raw.get("catalog_version"):
            return raw
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return dict(_BUILTIN)


def get_catalog_version() -> str:
    return str(load_catalog_dict().get("catalog_version") or "unknown")


def normalize_kex_for_match(kx: Optional[str]) -> str:
    """Fold common TLS/OpenSSL spellings for substring rules."""
    if not kx:
        return ""
    s = kx.strip()
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", "", s)
    return s.lower()


def score_key_exchange(name: Optional[str]) -> Tuple[float, str]:
    """Return (0–100 score, short rationale)."""
    cat = load_catalog_dict()
    nl = normalize_kex_for_match(name)
    if not nl:
        return 30.0, "Key exchange unknown"

    for rule in cat.get("kex_contains_rules") or []:
        toks = [_norm(t) for t in (rule.get("contains") or [])]
        if toks and any(t in nl for t in toks):
            sc = float(rule.get("score", 30))
            label = str(rule.get("label") or "KEX rule")
            return sc, f"KEX: {label}"

    return 30.0, f"Key exchange not catalog-matched ({(name or '')[:48]})"


def _rsa_tier_score(key_size: Optional[int], tiers: List[Dict[str, Any]]) -> Tuple[float, str]:
    ks = int(key_size or 0)
    if ks <= 0:
        return 15.0, "RSA (key size unknown)"
    for tier in tiers:
        mx = int(tier.get("max_bits", 999999))
        if ks <= mx:
            return float(tier.get("score", 15)), str(tier.get("label") or "RSA tier")
    return 24.0, "RSA (large modulus)"


def score_signature(name: Optional[str], key_size: Optional[int] = None) -> Tuple[float, str]:
    nl = _norm(name or "")
    if not nl:
        return 30.0, "Signature algorithm unknown"

    cat = load_catalog_dict()
    tiers = cat.get("rsa_signature_key_size_tiers") or _BUILTIN["rsa_signature_key_size_tiers"]

    for rule in cat.get("sig_contains_rules") or []:
        toks = [_norm(t) for t in (rule.get("contains") or [])]
        if not toks:
            continue
        if any(t in nl for t in toks):
            base = float(rule.get("score", 30))
            label = str(rule.get("label") or "signature")
            if "rsa" in nl and "ml" not in nl and "dilithium" not in nl:
                tier_score, tier_label = _rsa_tier_score(key_size, tiers)
                combined = min(base, tier_score)
                return combined, f"Signature: {tier_label}"
            return base, f"Signature: {label}"

    return 30.0, f"Signature not catalog-matched ({(name or '')[:48]})"


def score_hash(name: Optional[str]) -> Tuple[float, str]:
    nl = _norm(name or "")
    if not nl:
        return 50.0, "Hash unknown"

    cat = load_catalog_dict()
    for rule in cat.get("hash_contains_rules") or []:
        toks = [_norm(t) for t in (rule.get("contains") or [])]
        if toks and any(t in nl for t in toks):
            return float(rule.get("score", 50)), f"Hash: {rule.get('label') or name}"
    return 72.0, f"Hash posture ({name})"


def protocol_score(protocol_name: str) -> Tuple[float, str]:
    cat = load_catalog_dict()
    pmap = cat.get("protocol_scores") or _BUILTIN["protocol_scores"]
    name = (protocol_name or "").strip()
    if name in pmap:
        return float(pmap[name]), f"Protocol {name}"
    nu = name.upper().replace(" ", "")
    for k, v in pmap.items():
        if _norm(k) == _norm(name) or k.upper().replace(" ", "") in nu:
            return float(v), f"Protocol {k}"
    return 40.0, f"Protocol unknown ({name})"
