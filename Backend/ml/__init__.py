"""
Hybrid rule-based + ML quantum-safety assessment layer.

On import, if ``ML_ENABLED=True``, loads the ONNX inference engine and
ensemble policy as module-level singletons. If loading fails, both are
set to ``None`` so the scan pipeline degrades gracefully.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

_logger = logging.getLogger("ml")

ml_engine: Optional["MLInferenceEngine"] = None  # type: ignore[name-defined]
ensemble_policy: Optional["EnsemblePolicy"] = None  # type: ignore[name-defined]
feature_builder: Optional["FeatureBuilder"] = None  # type: ignore[name-defined]


def _boot() -> None:
    global ml_engine, ensemble_policy, feature_builder

    try:
        from ml.config import ml_config
    except Exception as exc:
        _logger.debug("ml.config import failed: %s", exc)
        return

    if not ml_config.ML_ENABLED:
        _logger.info("ML layer disabled (ML_ENABLED=False)")
        return

    try:
        from ml.feature_builder import FeatureBuilder as _FB

        feature_builder = _FB()
    except Exception as exc:
        _logger.error("Failed to init FeatureBuilder: %s", exc)
        return

    model_path = ml_config.ML_MODEL_PATH
    meta_path = model_path + ".meta.json"

    if not os.path.isfile(model_path):
        _logger.warning("ML model not found at %s — ML layer inactive", model_path)
        return

    try:
        from ml.inference_engine import MLInferenceEngine as _IE

        ml_engine = _IE(model_path, meta_path)
        _logger.info("ML inference engine loaded: %s", model_path)
    except Exception as exc:
        _logger.error("Failed to load ML inference engine: %s", exc)
        ml_engine = None
        return

    try:
        from ml.ensemble import EnsemblePolicy as _EP, EnsemblePolicyConfig

        cfg = EnsemblePolicyConfig(
            ml_override_enabled=ml_config.ML_OVERRIDE_ENABLED,
            t_high_vulnerable=ml_config.ML_T_HIGH_VULNERABLE,
            t_high_safe=ml_config.ML_T_HIGH_SAFE,
            ood_threshold=ml_config.ML_OOD_THRESHOLD,
            hard_deny_statuses=ml_config.hard_deny_list,
        )
        ensemble_policy = _EP(cfg)
        _logger.info("Ensemble policy ready (override=%s)", ml_config.ML_OVERRIDE_ENABLED)
    except Exception as exc:
        _logger.error("Failed to init EnsemblePolicy: %s", exc)
        ensemble_policy = None


_boot()
