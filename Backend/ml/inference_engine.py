"""
ONNX-based inference engine for the hybrid ML quantum-safety layer.

Loads a trained LightGBM ONNX model + optional calibrator sidecar,
runs per-component inference, and returns MLAssessment objects.
"""

from __future__ import annotations

import json
import math
import os
import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from pydantic import BaseModel, Field

from ml.feature_builder import (
    FEATURE_SCHEMA_VERSION,
    TEXT_HASH_DIM,
    ComponentFeatureVector,
)

NUM_CLASSES = 3


class MLAssessment(BaseModel):
    p_safe: float = 0.0
    p_partial: float = 0.0
    p_vulnerable: float = 0.0
    ood_score: float = 0.0
    predicted_class: int = 0
    model_id: str = ""
    model_version: str = ""
    inference_latency_ms: float = 0.0


_TABULAR_FIELDS = [
    "key_size", "log_key_size", "cert_chain_depth", "port",
    "tls_modern", "pqc_kem_observed", "hybrid_key_exchange",
    "is_symmetric", "is_asymmetric", "has_forward_secrecy", "is_known_weak",
    "category_encoded", "tls_version_encoded", "threat_encoded",
    "rule_quantum_status_encoded", "rule_confidence",
]


def _fv_to_numpy(fv: ComponentFeatureVector) -> np.ndarray:
    d = fv.model_dump()
    row: List[float] = []
    for f in _TABULAR_FIELDS:
        v = d[f]
        row.append(float(v) if not isinstance(v, bool) else float(int(v)))
    row.extend(float(x) for x in fv.text_hash_vector)
    return np.array(row, dtype=np.float32)


def _entropy(probs: np.ndarray) -> float:
    eps = 1e-9
    p = np.clip(probs, eps, 1.0)
    return float(-np.sum(p * np.log(p)))


class MLInferenceEngine:
    def __init__(self, model_path: str, meta_path: str) -> None:
        import onnxruntime as ort

        with open(meta_path, encoding="utf-8") as f:
            self._meta: Dict[str, Any] = json.load(f)

        schema = self._meta.get("feature_schema_version", "")
        if schema != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Feature schema mismatch: model expects {schema!r}, "
                f"builder provides {FEATURE_SCHEMA_VERSION!r}"
            )

        self._session = ort.InferenceSession(model_path)
        self._input_name = self._session.get_inputs()[0].name

        calib_name = self._meta.get("calibrator_path")
        self._calibrator = None
        if calib_name:
            calib_full = os.path.join(os.path.dirname(model_path), calib_name)
            if os.path.isfile(calib_full):
                self._calibrator = joblib.load(calib_full)

        self.model_id = ""
        self.model_version = ""
        reg_path = os.path.join(os.path.dirname(model_path), "registry.json")
        if os.path.isfile(reg_path):
            with open(reg_path, encoding="utf-8") as f:
                reg = json.load(f)
            self.model_id = reg.get("model_id", "")
            self.model_version = reg.get("model_version", "")

    def predict(self, feature_vector: ComponentFeatureVector) -> MLAssessment:
        return self.predict_batch([feature_vector])[0]

    def predict_batch(
        self, vectors: List[ComponentFeatureVector]
    ) -> List[MLAssessment]:
        X = np.stack([_fv_to_numpy(v) for v in vectors]).astype(np.float32)
        t0 = time.perf_counter()
        raw_out = self._session.run(None, {self._input_name: X})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        probs_raw = raw_out[1] if len(raw_out) > 1 else raw_out[0]

        if isinstance(probs_raw, list):
            n = len(probs_raw)
            prob_matrix = np.zeros((n, NUM_CLASSES), dtype=np.float64)
            for i, row_dict in enumerate(probs_raw):
                if isinstance(row_dict, dict):
                    for k, v in row_dict.items():
                        ci = int(k)
                        if 0 <= ci < NUM_CLASSES:
                            prob_matrix[i, ci] = float(v)
                elif isinstance(row_dict, (list, np.ndarray)):
                    arr = np.array(row_dict, dtype=np.float64)
                    prob_matrix[i, : len(arr)] = arr[: NUM_CLASSES]
        else:
            prob_matrix = np.array(probs_raw, dtype=np.float64)
            if prob_matrix.ndim == 1:
                prob_matrix = prob_matrix.reshape(1, -1)

        if self._calibrator is not None:
            try:
                cal_probs = self._calibrator.predict_proba(X)
                padded = np.zeros((cal_probs.shape[0], NUM_CLASSES), dtype=np.float64)
                classes = list(self._calibrator.classes_)
                for ci, c in enumerate(classes):
                    if int(c) < NUM_CLASSES:
                        padded[:, int(c)] = cal_probs[:, ci]
                row_sums = padded.sum(axis=1, keepdims=True)
                row_sums[row_sums == 0] = 1.0
                padded /= row_sums
                prob_matrix = padded
            except Exception:
                pass

        if prob_matrix.shape[1] < NUM_CLASSES:
            padded = np.zeros((prob_matrix.shape[0], NUM_CLASSES), dtype=np.float64)
            padded[:, : prob_matrix.shape[1]] = prob_matrix
            prob_matrix = padded

        row_sums = prob_matrix.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        prob_matrix /= row_sums

        per_item_ms = elapsed_ms / max(len(vectors), 1)

        results: List[MLAssessment] = []
        for i in range(len(vectors)):
            p = prob_matrix[i]
            ood = _entropy(p)
            results.append(
                MLAssessment(
                    p_safe=float(p[0]),
                    p_partial=float(p[1]),
                    p_vulnerable=float(p[2]),
                    ood_score=ood,
                    predicted_class=int(np.argmax(p)),
                    model_id=self.model_id,
                    model_version=self.model_version,
                    inference_latency_ms=round(per_item_ms, 3),
                )
            )
        return results

    def is_healthy(self) -> bool:
        try:
            dummy = ComponentFeatureVector()
            self.predict(dummy)
            return True
        except Exception:
            return False
