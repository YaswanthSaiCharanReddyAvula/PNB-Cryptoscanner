"""Tests for the label pipeline."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from app.db.models import AlgorithmCategory, CryptoComponent, QuantumStatus
from ml.label_pipeline import LabelPipeline, LabeledExample

_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def test_silver_maps_quantum_safe():
    lp = LabelPipeline()
    comp = CryptoComponent(
        name="ML-KEM-768", category=AlgorithmCategory.KEY_EXCHANGE,
        quantum_status=QuantumStatus.QUANTUM_SAFE, key_size=768,
    )
    exs = lp.generate_silver_labels(components=[comp])
    assert len(exs) == 1
    assert exs[0].label == 0
    assert exs[0].confidence_weight == 0.7


def test_silver_maps_vulnerable():
    lp = LabelPipeline()
    comp = CryptoComponent(
        name="RSA", category=AlgorithmCategory.SIGNATURE,
        quantum_status=QuantumStatus.VULNERABLE, key_size=2048,
    )
    exs = lp.generate_silver_labels(components=[comp])
    assert exs[0].label == 2
    assert exs[0].confidence_weight == 0.9


def test_silver_skips_unknown():
    """Components without a known quantum_status value are skipped."""
    lp = LabelPipeline()
    comp = CryptoComponent(
        name="MYSTERY", category=AlgorithmCategory.KEY_EXCHANGE,
        quantum_status=QuantumStatus.VULNERABLE,
    )
    comp_dict = comp.model_dump()
    comp_dict["quantum_status"] = "some_new_status"
    # Force an unknown status string via model_construct
    comp2 = CryptoComponent.model_construct(**comp_dict)
    exs = lp.generate_silver_labels(components=[comp2])
    assert len(exs) == 0


def test_synthetic_count_and_labels():
    lp = LabelPipeline()
    exs = lp.generate_synthetic_labels(n=200)
    assert len(exs) >= 150  # 30 bases * floor(200/30) = 180; capped at n
    assert len(exs) <= 200
    labels = {e.label for e in exs}
    assert 0 in labels
    assert 1 in labels
    assert 2 in labels
    for e in exs:
        assert e.label_source == "synthetic"
        assert e.confidence_weight == 0.85


def test_gold_csv():
    lp = LabelPipeline()
    path = str(_FIXTURE_DIR / "gold_sample.csv")
    exs = lp.load_gold_labels(path)
    assert len(exs) == 3
    assert exs[0].label == 0
    assert exs[0].label_source == "gold_manual"
    assert exs[0].confidence_weight == 1.0


def test_dedup_gold_wins():
    lp = LabelPipeline()
    silver = lp.generate_silver_labels(components=[
        CryptoComponent(
            name="RSA", category=AlgorithmCategory.SIGNATURE,
            quantum_status=QuantumStatus.VULNERABLE, key_size=2048,
        ),
    ])
    gold = lp.load_gold_labels(str(_FIXTURE_DIR / "gold_sample.csv"))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        out_path = f.name
    try:
        lp.export_dataset(out_path, silver=silver, gold=gold)
        with open(out_path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        rsa_rows = [r for r in lines if r["raw_component_name"] == "RSA"]
        assert len(rsa_rows) == 1
        assert rsa_rows[0]["label_source"] == "gold_manual"
    finally:
        os.unlink(out_path)
