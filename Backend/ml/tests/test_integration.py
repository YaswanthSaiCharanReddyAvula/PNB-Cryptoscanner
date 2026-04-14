"""
End-to-end integration test for the hybrid ML quantum-safety layer.

Uses mocked ONNX / MongoDB so no real model or database is required.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from app.db.models import AlgorithmCategory, CryptoComponent, QuantumStatus
from ml.ensemble import EnsemblePolicy, EnsemblePolicyConfig, RuleAssessment
from ml.feature_builder import ComponentFeatureVector, FeatureBuilder
from ml.inference_engine import MLAssessment
from ml.shadow_store import ShadowStore


COMPONENTS = [
    CryptoComponent(
        name="ML-KEM-768", category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=768, quantum_status=QuantumStatus.QUANTUM_SAFE,
        primary_quantum_threat="shor", host="safe.example",
    ),
    CryptoComponent(
        name="ECDHE-RSA-AES128-SHA256", category=AlgorithmCategory.KEY_EXCHANGE,
        quantum_status=QuantumStatus.VULNERABLE,
        primary_quantum_threat="shor", host="partial.example",
    ),
    CryptoComponent(
        name="AES-256-GCM", category=AlgorithmCategory.CIPHER,
        key_size=256, quantum_status=QuantumStatus.PARTIALLY_SAFE,
        primary_quantum_threat="grover", host="cipher.example",
    ),
    CryptoComponent(
        name="MD5", category=AlgorithmCategory.HASH,
        quantum_status=QuantumStatus.VULNERABLE,
        primary_quantum_threat="grover", host="weak.example",
    ),
    CryptoComponent(
        name="TLSv1.3", category=AlgorithmCategory.PROTOCOL,
        quantum_status=QuantumStatus.QUANTUM_SAFE,
        primary_quantum_threat="hndl", host="proto.example",
    ),
]


class FakeMLEngine:
    """Mock ML engine returning controlled probabilities."""

    def __init__(self, default_probs: tuple[float, float, float] = (0.3, 0.3, 0.4)):
        self._default = default_probs
        self.model_id = "test-model"
        self.model_version = "0.0.1"

    def predict(self, fv: ComponentFeatureVector) -> MLAssessment:
        p = self._default
        return MLAssessment(
            p_safe=p[0], p_partial=p[1], p_vulnerable=p[2],
            ood_score=0.4, predicted_class=int(np.argmax(p)),
            model_id=self.model_id, model_version=self.model_version,
            inference_latency_ms=0.5,
        )

    def is_healthy(self) -> bool:
        return True


fb = FeatureBuilder()


def test_feature_builder_on_all_components():
    for comp in COMPONENTS:
        fv = fb.build(comp)
        assert isinstance(fv, ComponentFeatureVector)
        assert fv.feature_schema_version == "1.0.0"


def test_mock_ml_engine():
    eng = FakeMLEngine((0.1, 0.1, 0.8))
    fv = fb.build(COMPONENTS[0])
    result = eng.predict(fv)
    assert abs(result.p_safe + result.p_partial + result.p_vulnerable - 1.0) < 0.01


def test_ensemble_on_all_components():
    eng = FakeMLEngine((0.3, 0.3, 0.4))
    cfg = EnsemblePolicyConfig(ml_override_enabled=False)
    pol = EnsemblePolicy(cfg)

    for comp in COMPONENTS:
        fv = fb.build(comp)
        ml_a = eng.predict(fv)
        rule = RuleAssessment(
            quantum_status_rule=comp.quantum_status.value.upper(),
            rule_confidence=0.8,
        )
        ea = pol.decide(rule, ml_a, comp)
        assert ea.final_quantum_status is not None
        assert ea.decision_path in ("rule_hard", "rule_ml_agree", "ml_escalate", "disagreement_review")


def test_md5_always_vulnerable_regardless_of_ml():
    eng = FakeMLEngine((0.9, 0.05, 0.05))
    for override in (False, True):
        cfg = EnsemblePolicyConfig(ml_override_enabled=override)
        pol = EnsemblePolicy(cfg)
        comp = COMPONENTS[3]  # MD5
        fv = fb.build(comp)
        ml_a = eng.predict(fv)
        rule = RuleAssessment(quantum_status_rule="VULNERABLE", rule_confidence=1.0)
        ea = pol.decide(rule, ml_a, comp)
        assert ea.final_quantum_status == "VULNERABLE", (
            f"MD5 should always be VULNERABLE, got {ea.final_quantum_status} "
            f"(override={override})"
        )


def test_shadow_mode_rule_always_wins():
    eng = FakeMLEngine((0.05, 0.05, 0.9))
    cfg = EnsemblePolicyConfig(ml_override_enabled=False)
    pol = EnsemblePolicy(cfg)

    for comp in COMPONENTS:
        fv = fb.build(comp)
        ml_a = eng.predict(fv)
        status = comp.quantum_status.value.upper()
        if "MD5" in (comp.name or "").upper():
            continue  # hard-deny overrides rule_status
        rule = RuleAssessment(quantum_status_rule=status, rule_confidence=0.8)
        ea = pol.decide(rule, ml_a, comp)
        assert ea.final_quantum_status == status, (
            f"Shadow mode: expected {status}, got {ea.final_quantum_status}"
        )


@pytest.mark.asyncio
async def test_shadow_store_save():
    mock_collection = MagicMock()
    mock_collection.insert_one = AsyncMock()
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_collection)

    store = ShadowStore(mock_db)

    eng = FakeMLEngine()
    cfg = EnsemblePolicyConfig(ml_override_enabled=False)
    pol = EnsemblePolicy(cfg)
    comp = COMPONENTS[0]
    fv = fb.build(comp)
    ml_a = eng.predict(fv)
    rule = RuleAssessment(quantum_status_rule="QUANTUM_SAFE", rule_confidence=0.9)
    ea = pol.decide(rule, ml_a, comp)

    await store.save(
        scan_id="test-scan-001",
        component_name=comp.name,
        component_category=comp.category.value,
        component_key_size=comp.key_size,
        component_host=comp.host or "",
        ml_assessment=ml_a,
        ensemble_assessment=ea,
    )
    mock_collection.insert_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_shadow_store_disagreement_rate():
    mock_collection = MagicMock()
    mock_collection.count_documents = AsyncMock(side_effect=[10, 3])
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_collection)

    store = ShadowStore(mock_db)
    rate = await store.get_disagreement_rate(since_hours=24)
    assert isinstance(rate, float)
    assert abs(rate - 0.3) < 0.01


def test_no_exceptions_full_pipeline():
    eng = FakeMLEngine()
    cfg = EnsemblePolicyConfig(ml_override_enabled=True)
    pol = EnsemblePolicy(cfg)

    for comp in COMPONENTS:
        fv = fb.build(comp)
        ml_a = eng.predict(fv)
        rule = RuleAssessment(
            quantum_status_rule=comp.quantum_status.value.upper(),
            rule_confidence=0.8,
        )
        ea = pol.decide(rule, ml_a, comp)
        assert ea is not None
