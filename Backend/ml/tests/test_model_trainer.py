"""Tests for QuantumClassifier trainer."""

from __future__ import annotations

import os
import tempfile

import numpy as np
import pytest

from ml.label_pipeline import LabelPipeline, LabeledExample
from ml.model_trainer import QuantumClassifier


def _synthetic_examples(n: int = 100) -> list[LabeledExample]:
    lp = LabelPipeline(seed=99)
    silver = lp.generate_silver_labels()
    synth = lp.generate_synthetic_labels(n=n)
    return silver + synth


def test_prepare_features_shapes():
    clf = QuantumClassifier()
    exs = _synthetic_examples(60)
    X, y, w = clf.prepare_features(exs)
    assert X.shape[0] == len(exs)
    assert X.shape[1] == 16 + 256
    assert y.shape == (len(exs),)
    assert w.shape == (len(exs),)


def test_train_end_to_end():
    clf = QuantumClassifier()
    exs = _synthetic_examples(100)
    metrics = clf.train(exs, holdout_fraction=0.3)
    assert "macro_f1" in metrics
    assert "per_class_f1" in metrics
    assert "critical_miss_rate" in metrics
    assert "brier_score" in metrics
    assert "calibration_ece" in metrics
    assert 0 <= metrics["macro_f1"] <= 1
    assert 0 <= metrics["critical_miss_rate"] <= 1


def test_evaluate_returns_all_keys():
    clf = QuantumClassifier()
    exs = _synthetic_examples(80)
    clf.train(exs, holdout_fraction=0.3)
    X, y, _ = clf.prepare_features(exs)
    m = clf.evaluate(X, y)
    for key in ["macro_f1", "per_class_f1", "critical_miss_rate", "brier_score", "calibration_ece"]:
        assert key in m


def test_critical_miss_rate_handcrafted():
    y_true = np.array([2, 2, 2, 0, 0])
    preds = np.array([0, 2, 2, 0, 0])
    truly_vuln = y_true == 2
    pred_safe = preds == 0
    n_vuln = int(truly_vuln.sum())
    critical_miss = int((truly_vuln & pred_safe).sum())
    cmr = critical_miss / max(n_vuln, 1)
    assert abs(cmr - 1.0 / 3.0) < 1e-6


def test_export_onnx():
    clf = QuantumClassifier()
    exs = _synthetic_examples(80)
    clf.train(exs, holdout_fraction=0.3)
    with tempfile.TemporaryDirectory() as td:
        onnx_path = os.path.join(td, "model.onnx")
        clf.export_onnx(onnx_path)
        assert os.path.isfile(onnx_path)
        assert os.path.isfile(onnx_path + ".meta.json")
