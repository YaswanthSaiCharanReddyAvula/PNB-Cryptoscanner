"""
ML model trainer for the hybrid quantum-safety classifier.

Trains a LightGBM multiclass classifier, calibrates with Platt scaling,
evaluates, and exports to ONNX with a sidecar metadata JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, brier_score_loss, f1_score

from ml.feature_builder import FEATURE_SCHEMA_VERSION, ComponentFeatureVector
from ml.label_pipeline import LabeledExample

CLASS_NAMES = {0: "QUANTUM_SAFE", 1: "PARTIALLY_SAFE", 2: "VULNERABLE"}
NUM_CLASSES = 3

_TABULAR_FIELDS = [
    "key_size", "log_key_size", "cert_chain_depth", "port",
    "tls_modern", "pqc_kem_observed", "hybrid_key_exchange",
    "is_symmetric", "is_asymmetric", "has_forward_secrecy", "is_known_weak",
    "category_encoded", "tls_version_encoded", "threat_encoded",
    "rule_quantum_status_encoded", "rule_confidence",
]


def _fv_to_tabular(fv: ComponentFeatureVector) -> List[float]:
    d = fv.model_dump()
    row: List[float] = []
    for f in _TABULAR_FIELDS:
        v = d[f]
        row.append(float(v) if not isinstance(v, bool) else float(int(v)))
    return row


class QuantumClassifier:
    def __init__(self) -> None:
        self.model: Any = None
        self.calibrated_model: Any = None
        self._feature_names: List[str] = []

    def prepare_features(
        self, examples: List[LabeledExample]
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        X_tab: List[List[float]] = []
        X_text: List[List[int]] = []
        y: List[int] = []
        w: List[float] = []
        for ex in examples:
            fv = ex.feature_vector
            X_tab.append(_fv_to_tabular(fv))
            X_text.append(fv.text_hash_vector)
            y.append(ex.label)
            w.append(ex.confidence_weight)
        X = np.hstack([np.array(X_tab, dtype=np.float32),
                        np.array(X_text, dtype=np.float32)])
        self._feature_names = _TABULAR_FIELDS + [f"hash_{i}" for i in range(256)]
        return X, np.array(y, dtype=np.int32), np.array(w, dtype=np.float32)

    def train(
        self, examples: List[LabeledExample], holdout_fraction: float = 0.2
    ) -> Dict[str, Any]:
        import lightgbm as lgb

        X, y, w = self.prepare_features(examples)
        split_idx = int(len(examples) * (1 - holdout_fraction))
        X_train, X_hold = X[:split_idx], X[split_idx:]
        y_train, y_hold = y[:split_idx], y[split_idx:]
        w_train, w_hold = w[:split_idx], w[split_idx:]

        class_w = {0: 1.0, 1: 1.0, 2: 2.0}
        w_adj_train = w_train * np.array([class_w.get(int(c), 1.0) for c in y_train], dtype=np.float32)
        w_adj_hold = w_hold * np.array([class_w.get(int(c), 1.0) for c in y_hold], dtype=np.float32)

        self.model = lgb.LGBMClassifier(
            n_estimators=500,
            learning_rate=0.05,
            max_depth=6,
            num_class=NUM_CLASSES,
            objective="multiclass",
            metric="multi_logloss",
            n_jobs=-1,
            random_state=42,
            verbose=-1,
        )
        self.model.fit(
            X_train, y_train,
            sample_weight=w_adj_train,
            eval_set=[(X_hold, y_hold)],
            callbacks=[lgb.early_stopping(50, verbose=False)],
        )

        self.calibrated_model = CalibratedClassifierCV(
            self.model, cv=2, method="sigmoid"
        )
        self.calibrated_model.fit(X_hold, y_hold, sample_weight=w_adj_hold)

        metrics = self.evaluate(X_hold, y_hold)
        return metrics

    def _full_proba(self, X: np.ndarray) -> np.ndarray:
        """predict_proba padded to always have NUM_CLASSES columns."""
        raw = self.calibrated_model.predict_proba(X)
        if raw.shape[1] >= NUM_CLASSES:
            return raw[:, :NUM_CLASSES]
        padded = np.zeros((raw.shape[0], NUM_CLASSES), dtype=np.float64)
        classes = list(self.calibrated_model.classes_)
        for i, c in enumerate(classes):
            if int(c) < NUM_CLASSES:
                padded[:, int(c)] = raw[:, i]
        row_sums = padded.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        padded /= row_sums
        return padded

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        probs = self._full_proba(X)
        preds = np.argmax(probs, axis=1)

        acc = float(accuracy_score(y, preds))
        macro = float(f1_score(y, preds, average="macro", zero_division=0))

        per_class_f1: Dict[int, float] = {}
        per_class_acc: Dict[int, float] = {}
        per_class_count: Dict[int, int] = {}
        for c in range(NUM_CLASSES):
            mask = y == c
            n_c = int(mask.sum())
            per_class_count[c] = n_c
            per_class_f1[c] = float(
                f1_score(mask, preds == c, zero_division=0)
            )
            if n_c > 0:
                per_class_acc[c] = float((preds[mask] == c).sum() / n_c)
            else:
                per_class_acc[c] = 0.0

        truly_vuln = y == 2
        pred_safe = preds == 0
        n_vuln = int(truly_vuln.sum())
        critical_miss = int((truly_vuln & pred_safe).sum())
        cmr = critical_miss / max(n_vuln, 1)

        brier_parts: List[float] = []
        for c in range(NUM_CLASSES):
            brier_parts.append(float(brier_score_loss(y == c, probs[:, c])))
        brier = float(np.mean(brier_parts))

        ece = self._ece(probs, y)

        report = {
            "accuracy": round(acc, 4),
            "accuracy_pct": f"{acc * 100:.2f}%",
            "macro_f1": round(macro, 4),
            "per_class_f1": {k: round(v, 4) for k, v in per_class_f1.items()},
            "per_class_accuracy": {
                k: f"{v * 100:.1f}% ({per_class_count[k]} samples)"
                for k, v in per_class_acc.items()
            },
            "critical_miss_rate": round(cmr, 4),
            "brier_score": round(brier, 4),
            "calibration_ece": round(ece, 4),
        }

        print("=" * 60)
        print("EVALUATION REPORT")
        print(f"  Overall accuracy:     {report['accuracy_pct']}")
        print(f"  Macro F1:             {report['macro_f1']}")
        print(f"  Critical miss rate:   {report['critical_miss_rate']}")
        print(f"  Brier score:          {report['brier_score']}")
        print(f"  Calibration ECE:      {report['calibration_ece']}")
        print("-" * 60)
        for c in range(NUM_CLASSES):
            label = CLASS_NAMES.get(c, f"class_{c}")
            print(f"  {label:20s}  F1={per_class_f1[c]:.4f}  "
                  f"Acc={per_class_acc[c] * 100:.1f}%  "
                  f"(n={per_class_count[c]})")
        print("=" * 60)
        return report

    @staticmethod
    def _ece(probs: np.ndarray, y: np.ndarray, n_bins: int = 10) -> float:
        confidences = np.max(probs, axis=1)
        predictions = np.argmax(probs, axis=1)
        accuracies = (predictions == y).astype(float)
        bin_edges = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        for i in range(n_bins):
            mask = (confidences > bin_edges[i]) & (confidences <= bin_edges[i + 1])
            n = mask.sum()
            if n == 0:
                continue
            avg_conf = confidences[mask].mean()
            avg_acc = accuracies[mask].mean()
            ece += (n / len(y)) * abs(avg_acc - avg_conf)
        return float(ece)

    def export_onnx(self, output_path: str) -> None:
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType

        n_features = len(self._feature_names)
        initial_type = [("X", FloatTensorType([None, n_features]))]
        onnx_model = convert_lightgbm(
            self.model,
            initial_types=initial_type,
            target_opset=15,
        )
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        calib_path = output_path + ".calibrator.joblib"
        joblib.dump(self.calibrated_model, calib_path)

        meta = {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": self._feature_names,
            "class_mapping": {str(k): v for k, v in CLASS_NAMES.items()},
            "n_features": n_features,
            "calibrator_path": os.path.basename(calib_path),
        }
        meta_path = output_path + ".meta.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        print(f"ONNX exported to {output_path} ({meta_path})")

    def save_model_registry_entry(
        self, metrics: Dict[str, Any], output_path: str,
        training_data_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        data_hash = ""
        if training_data_path and os.path.isfile(training_data_path):
            h = hashlib.md5()
            with open(training_data_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            data_hash = h.hexdigest()

        entry = {
            "model_id": str(uuid.uuid4()),
            "model_version": "1.0.0",
            "training_data_hash": data_hash,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "metrics": metrics,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "onnx_path": output_path,
        }
        registry_path = str(Path(output_path).parent / "registry.json")
        os.makedirs(os.path.dirname(registry_path) or ".", exist_ok=True)
        with open(registry_path, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)
        print(f"Registry entry saved to {registry_path}")
        return entry
