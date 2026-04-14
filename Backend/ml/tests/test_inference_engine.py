"""Tests for MLInferenceEngine."""

from __future__ import annotations

import json
import os
import tempfile

import numpy as np
import pytest

from ml.feature_builder import FEATURE_SCHEMA_VERSION, ComponentFeatureVector, FeatureBuilder
from ml.inference_engine import MLInferenceEngine, MLAssessment
from ml.label_pipeline import LabelPipeline
from ml.model_trainer import QuantumClassifier


@pytest.fixture(scope="module")
def trained_model_dir():
    """Train a tiny model and export to a temp dir for inference tests."""
    lp = LabelPipeline(seed=77)
    exs = lp.generate_silver_labels() + lp.generate_synthetic_labels(n=200)
    clf = QuantumClassifier()
    clf.train(exs, holdout_fraction=0.25)
    td = tempfile.mkdtemp()
    onnx_path = os.path.join(td, "model.onnx")
    clf.export_onnx(onnx_path)
    clf.save_model_registry_entry({}, onnx_path)
    yield td


@pytest.fixture(scope="module")
def engine(trained_model_dir):
    onnx_path = os.path.join(trained_model_dir, "model.onnx")
    meta_path = onnx_path + ".meta.json"
    return MLInferenceEngine(onnx_path, meta_path)


def test_predict_probs_sum_to_one(engine):
    fv = ComponentFeatureVector()
    result = engine.predict(fv)
    total = result.p_safe + result.p_partial + result.p_vulnerable
    assert abs(total - 1.0) < 0.05


def test_ood_populated(engine):
    fv = ComponentFeatureVector()
    result = engine.predict(fv)
    assert result.ood_score >= 0.0


def test_latency_populated(engine):
    fv = ComponentFeatureVector()
    result = engine.predict(fv)
    assert result.inference_latency_ms >= 0.0


def test_batch_predict(engine):
    fvs = [ComponentFeatureVector() for _ in range(5)]
    results = engine.predict_batch(fvs)
    assert len(results) == 5
    for r in results:
        assert abs(r.p_safe + r.p_partial + r.p_vulnerable - 1.0) < 0.05


def test_version_mismatch(trained_model_dir):
    onnx_path = os.path.join(trained_model_dir, "model.onnx")
    meta_path = onnx_path + ".meta.json"
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    meta["feature_schema_version"] = "0.0.0-wrong"
    bad_meta = os.path.join(trained_model_dir, "bad.meta.json")
    with open(bad_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f)
    with pytest.raises(ValueError, match="schema mismatch"):
        MLInferenceEngine(onnx_path, bad_meta)


def test_is_healthy(engine):
    assert engine.is_healthy() is True
