"""Golden-vector tests for FeatureBuilder."""

from __future__ import annotations

import math

import pytest

from app.db.models import AlgorithmCategory, CryptoComponent, QuantumStatus, TLSInfo
from ml.feature_builder import FEATURE_SCHEMA_VERSION, FeatureBuilder, TEXT_HASH_DIM

fb = FeatureBuilder()


def _comp(**kw) -> CryptoComponent:
    defaults = {
        "name": "X",
        "category": AlgorithmCategory.KEY_EXCHANGE,
        "usage_context": "",
    }
    defaults.update(kw)
    return CryptoComponent.model_validate(defaults)


# 1. ML-KEM-768 / key_exchange / key_size=768
def test_mlkem_768():
    c = _comp(name="ML-KEM-768", category=AlgorithmCategory.KEY_EXCHANGE, key_size=768)
    v = fb.build(c)
    assert v.is_asymmetric is True
    assert v.is_known_weak is False
    assert v.tls_modern is False
    assert v.category_encoded == 0
    assert v.key_size == 768
    assert abs(v.log_key_size - math.log2(768)) < 0.01


# 2. SSLv2 / key_exchange + TLS 1.0
def test_sslv2_tls10():
    c = _comp(name="SSLv2", category=AlgorithmCategory.KEY_EXCHANGE)
    tls = TLSInfo(host="x", port=443, tls_version="TLSv1.0")
    v = fb.build(c, tls_info=tls)
    assert v.tls_version_encoded == 0
    assert v.tls_modern is False


# 3. ECDHE-RSA-AES128-SHA256 / key_exchange → has_forward_secrecy
def test_ecdhe_rsa():
    c = _comp(name="ECDHE-RSA-AES128-SHA256", category=AlgorithmCategory.KEY_EXCHANGE)
    v = fb.build(c)
    assert v.has_forward_secrecy is True


# 4. MD5 / hash → is_known_weak, is_symmetric
def test_md5_hash():
    c = _comp(name="MD5", category=AlgorithmCategory.HASH)
    v = fb.build(c)
    assert v.is_known_weak is True
    assert v.is_symmetric is True
    assert v.is_asymmetric is False


# 5. AES-256-GCM / cipher / key_size=256 → is_symmetric, log_key_size≈8.0
def test_aes256():
    c = _comp(name="AES-256-GCM", category=AlgorithmCategory.CIPHER, key_size=256)
    v = fb.build(c)
    assert v.is_symmetric is True
    assert abs(v.log_key_size - 8.0) < 0.01


# 6. Unknown-Algo-XYZ / key_exchange → no crash, not weak
def test_unknown_algo():
    c = _comp(name="Unknown-Algo-XYZ", category=AlgorithmCategory.KEY_EXCHANGE)
    v = fb.build(c)
    assert v.is_known_weak is False
    assert v.feature_schema_version == FEATURE_SCHEMA_VERSION


# 7. Empty name / category=protocol → no crash, defaults
def test_empty_name():
    c = _comp(name="", category=AlgorithmCategory.PROTOCOL)
    v = fb.build(c)
    assert v.key_size == 0
    assert v.log_key_size == 0.0
    assert v.category_encoded == 4
    assert len(v.text_hash_vector) == TEXT_HASH_DIM


# 8. Rule passthrough: VULNERABLE + confidence=1.0
def test_rule_passthrough():
    c = _comp(name="RSA-1024", category=AlgorithmCategory.KEY_EXCHANGE)
    rule = {"quantum_status": "vulnerable", "confidence": 1.0}
    v = fb.build(c, rule_assessment=rule)
    assert v.rule_quantum_status_encoded == 2
    assert v.rule_confidence == 1.0
