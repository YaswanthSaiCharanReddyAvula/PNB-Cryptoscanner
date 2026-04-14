"""
Runnable training script.

Usage:
    cd Backend
    python -m ml.train_model
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ml.label_pipeline import LabelPipeline, LabeledExample
from ml.model_trainer import QuantumClassifier

DATA_DIR = Path(__file__).resolve().parent / "data"
MODEL_DIR = Path(__file__).resolve().parent / "models"
DATASET_PATH = DATA_DIR / "training_data.jsonl"
ONNX_PATH = MODEL_DIR / "quantum_classifier_v1.onnx"


def _load_jsonl(path: Path) -> list[LabeledExample]:
    examples: list[LabeledExample] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            examples.append(LabeledExample.model_validate_json(line))
    return examples


def main() -> None:
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}, generating…")
        lp = LabelPipeline()
        silver = lp.generate_silver_labels()
        synthetic = lp.generate_synthetic_labels(n=2000)
        gold_path = DATA_DIR / "gold_labels.csv"
        gold = lp.load_gold_labels(str(gold_path)) if gold_path.exists() else []
        lp.export_dataset(str(DATASET_PATH), silver=silver, synthetic=synthetic, gold=gold)

    print(f"Loading dataset from {DATASET_PATH}")
    examples = _load_jsonl(DATASET_PATH)
    print(f"Loaded {len(examples)} examples")

    clf = QuantumClassifier()
    metrics = clf.train(examples)

    cmr = metrics["critical_miss_rate"]
    if cmr > 0.05:
        print(f"FATAL: critical_miss_rate = {cmr} > 0.05 threshold")
        sys.exit(1)

    clf.export_onnx(str(ONNX_PATH))
    clf.save_model_registry_entry(
        metrics, str(ONNX_PATH), training_data_path=str(DATASET_PATH)
    )
    print("Training complete.")


if __name__ == "__main__":
    main()
