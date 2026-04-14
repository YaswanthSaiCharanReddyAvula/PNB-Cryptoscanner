"""
Feature builder for the hybrid ML quantum-safety assessment layer.

Converts a CryptoComponent (plus optional TLS context and rule verdict)
into a fixed-width numeric vector suitable for tree-based or linear models.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.db.models import AlgorithmCategory, CryptoComponent, TLSInfo

FEATURE_SCHEMA_VERSION = "1.0.0"

_CATEGORY_ENC: Dict[str, int] = {
    AlgorithmCategory.KEY_EXCHANGE.value: 0,
    AlgorithmCategory.SIGNATURE.value: 1,
    AlgorithmCategory.CIPHER.value: 2,
    AlgorithmCategory.HASH.value: 3,
    AlgorithmCategory.PROTOCOL.value: 4,
}
_CATEGORY_OTHER = 5

_TLS_VER_ENC: Dict[str, int] = {"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3}
_TLS_VER_DEFAULT = 2

_THREAT_ENC: Dict[str, int] = {"shor": 0, "grover": 1, "hndl": 2, "none": 3}
_THREAT_DEFAULT = 3

_QSTATUS_ENC: Dict[str, int] = {
    "quantum_safe": 0,
    "partially_safe": 1,
    "vulnerable": 2,
    "unknown": 3,
}

_KNOWN_WEAK_TOKENS = ("md5", "rc4", "des", "null", "export", "anon")

_ASYMMETRIC_CATEGORIES = {
    AlgorithmCategory.KEY_EXCHANGE.value,
    AlgorithmCategory.SIGNATURE.value,
}
_SYMMETRIC_CATEGORIES = {
    AlgorithmCategory.CIPHER.value,
    AlgorithmCategory.HASH.value,
}

TEXT_HASH_DIM = 256
TEXT_HASH_MAX_COUNT = 10


class ComponentFeatureVector(BaseModel):
    """Fixed-width feature representation of a single CryptoComponent."""

    # Numeric
    key_size: int = 0
    log_key_size: float = 0.0
    cert_chain_depth: int = 1
    port: int = 443

    # Boolean
    tls_modern: bool = False
    pqc_kem_observed: bool = False
    hybrid_key_exchange: bool = False
    is_symmetric: bool = False
    is_asymmetric: bool = False
    has_forward_secrecy: bool = False
    is_known_weak: bool = False

    # Categorical (label-encoded)
    category_encoded: int = _CATEGORY_OTHER
    tls_version_encoded: int = _TLS_VER_DEFAULT
    threat_encoded: int = _THREAT_DEFAULT

    # Rule pass-through
    rule_quantum_status_encoded: int = 3
    rule_confidence: float = 0.5

    # Text hash (char n-gram hashing trick)
    text_hash_vector: List[int] = Field(
        default_factory=lambda: [0] * TEXT_HASH_DIM
    )

    # Metadata (not used as ML features)
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    component_id: Optional[str] = None
    raw_text: str = ""


def _extract_tls_version_key(tls_version: Optional[str]) -> str:
    """Pull the 'x.y' portion from strings like 'TLSv1.3', 'SSLv3', '1.2'."""
    if not tls_version:
        return ""
    s = tls_version.strip()
    m = re.search(r"(\d+\.\d+)", s)
    if m:
        return m.group(1)
    m = re.search(r"(\d+)", s)
    if m:
        return m.group(1) + ".0"
    return ""


def _char_ngrams(text: str, ns: tuple[int, ...] = (2, 3)) -> List[str]:
    grams: List[str] = []
    for n in ns:
        for i in range(len(text) - n + 1):
            grams.append(text[i : i + n])
    return grams


def _text_hash(text: str) -> List[int]:
    vec = [0] * TEXT_HASH_DIM
    grams = _char_ngrams(text.lower(), (2, 3))
    for g in grams:
        idx = hash(g) % TEXT_HASH_DIM
        vec[idx] = min(vec[idx] + 1, TEXT_HASH_MAX_COUNT)
    return vec


class FeatureBuilder:
    """Builds a ComponentFeatureVector from a CryptoComponent and context."""

    def build(
        self,
        component: CryptoComponent,
        tls_info: Optional[TLSInfo] = None,
        rule_assessment: Optional[Dict[str, Any]] = None,
    ) -> ComponentFeatureVector:
        name = component.name or ""
        name_lower = name.lower()
        cat_val = (
            component.category.value
            if isinstance(component.category, AlgorithmCategory)
            else str(component.category)
        )

        ks = int(component.key_size or 0)
        log_ks = math.log2(ks) if ks > 0 else 0.0

        tls_ver_key = ""
        tls_modern = False
        pqc_kem = False
        hybrid_kex = False
        port = 443
        cert_chain_depth = 1

        if tls_info is not None:
            tls_ver_key = _extract_tls_version_key(tls_info.tls_version)
            tls_modern = tls_ver_key == "1.3"
            pqc_kem = bool(tls_info.pqc_kem_observed)
            hybrid_kex = bool(tls_info.hybrid_key_exchange)
            port = int(tls_info.port) if tls_info.port else 443
            cert_chain_depth = max(1, len(tls_info.cert_chain)) if tls_info.cert_chain else 1

        has_fs = ("dhe" in name_lower) or ("ecdhe" in name_lower)
        is_weak = any(tok in name_lower for tok in _KNOWN_WEAK_TOKENS)

        cat_enc = _CATEGORY_ENC.get(cat_val, _CATEGORY_OTHER)
        tls_enc = _TLS_VER_ENC.get(tls_ver_key, _TLS_VER_DEFAULT)

        threat_raw = (component.primary_quantum_threat or "").strip().lower()
        threat_enc = _THREAT_ENC.get(threat_raw, _THREAT_DEFAULT)

        rule = rule_assessment or {}
        r_status = str(rule.get("quantum_status", "unknown")).lower().replace(" ", "_")
        r_status_enc = _QSTATUS_ENC.get(r_status, 3)
        r_conf = float(rule.get("confidence", 0.5))

        raw_text = f"{name} {cat_val} {component.usage_context or ''}".strip()
        thash = _text_hash(raw_text)

        return ComponentFeatureVector(
            key_size=ks,
            log_key_size=round(log_ks, 6),
            cert_chain_depth=cert_chain_depth,
            port=port,
            tls_modern=tls_modern,
            pqc_kem_observed=pqc_kem,
            hybrid_key_exchange=hybrid_kex,
            is_symmetric=(cat_val in _SYMMETRIC_CATEGORIES),
            is_asymmetric=(cat_val in _ASYMMETRIC_CATEGORIES),
            has_forward_secrecy=has_fs,
            is_known_weak=is_weak,
            category_encoded=cat_enc,
            tls_version_encoded=tls_enc,
            threat_encoded=threat_enc,
            rule_quantum_status_encoded=r_status_enc,
            rule_confidence=r_conf,
            text_hash_vector=thash,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            component_id=None,
            raw_text=raw_text,
        )
