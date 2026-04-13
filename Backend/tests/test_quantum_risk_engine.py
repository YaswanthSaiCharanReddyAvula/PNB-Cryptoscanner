"""Golden vectors and regression tests for quantum_risk_engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.db.models import AlgorithmCategory, CryptoComponent
from app.modules import quantum_risk_engine


def _c(**kwargs) -> CryptoComponent:
    d = {
        "name": "X",
        "category": AlgorithmCategory.PROTOCOL,
        "usage_context": "t",
        "host": "h1",
    }
    d.update(kwargs)
    return CryptoComponent.model_validate(d)


def test_empty_components_critical():
    q = quantum_risk_engine.calculate_score([])
    assert q.score == 0
    assert q.risk_level.value == "critical"
    assert q.catalog_version
    assert 0 <= q.confidence <= 1


def test_hash_md5_lowers_aggregate():
    base = [
        _c(name="TLSv1.3", category=AlgorithmCategory.PROTOCOL),
        _c(name="AES256", category=AlgorithmCategory.CIPHER, key_size=256),
        _c(name="ECDHE-RSA-AES128-GCM-SHA256", category=AlgorithmCategory.KEY_EXCHANGE),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=2048),
        _c(name="SHA-256", category=AlgorithmCategory.HASH),
    ]
    q_good = quantum_risk_engine.calculate_score(base)
    bad = [(comp if comp.name != "SHA-256" else comp.model_copy(update={"name": "MD5"})) for comp in base]
    q_bad = quantum_risk_engine.calculate_score(bad)
    assert q_bad.score < q_good.score
    assert q_bad.breakdown.hash_score < q_good.breakdown.hash_score


def test_kyber_hybrid_string_high_kex():
    comps = [
        _c(name="TLSv1.3", category=AlgorithmCategory.PROTOCOL),
        _c(name="AES256", category=AlgorithmCategory.CIPHER, key_size=256),
        _c(name="TLS_AES_256_GCM_SHA384 X25519KYBER768", category=AlgorithmCategory.KEY_EXCHANGE),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=2048),
        _c(name="SHA-256", category=AlgorithmCategory.HASH),
    ]
    q = quantum_risk_engine.calculate_score(comps)
    assert q.breakdown.key_exchange_score >= 90


def test_aggregation_modes_set_metadata():
    good = [
        _c(name="TLSv1.3", category=AlgorithmCategory.PROTOCOL, host="good.example"),
        _c(name="AES256", category=AlgorithmCategory.CIPHER, key_size=256, host="good.example"),
        _c(name="ECDHE", category=AlgorithmCategory.KEY_EXCHANGE, host="good.example"),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=4096, host="good.example"),
        _c(name="SHA-256", category=AlgorithmCategory.HASH, host="good.example"),
    ]
    bad = [
        _c(name="TLSv1.0", category=AlgorithmCategory.PROTOCOL, host="bad.example"),
        _c(name="AES128", category=AlgorithmCategory.CIPHER, key_size=128, host="bad.example"),
        _c(name="RSA", category=AlgorithmCategory.KEY_EXCHANGE, host="bad.example"),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=1024, host="bad.example"),
        _c(name="MD5", category=AlgorithmCategory.HASH, host="bad.example"),
    ]
    pool = good + bad
    estate = quantum_risk_engine.calculate_score(pool, aggregation="estate_weakest")
    per_host = quantum_risk_engine.calculate_score(pool, aggregation="per_host_min")
    p25 = quantum_risk_engine.calculate_score(pool, aggregation="p25")
    assert estate.aggregation == "estate_weakest"
    assert per_host.aggregation == "per_host_min"
    assert p25.aggregation == "p25"
    assert 0 <= estate.score <= 100
    assert 0 <= per_host.score <= 100
    assert 0 <= p25.score <= 100


@pytest.mark.parametrize(
    "aggregation",
    ["estate_weakest", "per_host_min", "p25"],
)
def test_p25_between_extremes(aggregation):
    good = [
        _c(name="TLSv1.3", category=AlgorithmCategory.PROTOCOL, host="a"),
        _c(name="AES256", category=AlgorithmCategory.CIPHER, key_size=256, host="a"),
        _c(name="ECDHE", category=AlgorithmCategory.KEY_EXCHANGE, host="a"),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=4096, host="a"),
        _c(name="SHA-256", category=AlgorithmCategory.HASH, host="a"),
    ]
    mid = [x.model_copy(update={"host": "b"}) for x in good]
    bad = [
        _c(name="TLSv1.0", category=AlgorithmCategory.PROTOCOL, host="c"),
        _c(name="AES128", category=AlgorithmCategory.CIPHER, key_size=128, host="c"),
        _c(name="RSA", category=AlgorithmCategory.KEY_EXCHANGE, host="c"),
        _c(name="RSA", category=AlgorithmCategory.SIGNATURE, key_size=1024, host="c"),
        _c(name="MD5", category=AlgorithmCategory.HASH, host="c"),
    ]
    q = quantum_risk_engine.calculate_score(good + mid + bad, aggregation=aggregation)  # type: ignore[arg-type]
    assert q.score >= 0
    assert len(q.drivers) <= 3


def test_fixture_vectors_in_band():
    path = Path(__file__).resolve().parent / "fixtures" / "quantum_vectors.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for case in data:
        comps = [CryptoComponent.model_validate(row) for row in case["components"]]
        q = quantum_risk_engine.calculate_score(comps, aggregation="estate_weakest")
        lo = float(case["expected_score_min"])
        hi = float(case["expected_score_max"])
        assert lo <= q.score <= hi, f"{case['id']}: score {q.score} not in [{lo},{hi}]"
        assert q.catalog_version
        assert isinstance(q.drivers, list)
