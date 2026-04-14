"""
ML monitoring API endpoints.

Mounted under ``/api/ml`` in the main FastAPI app. All endpoints require
authentication via the existing ``get_current_user`` dependency.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.core.deps import get_current_user
from app.db.connection import get_database

router = APIRouter(prefix="/api/ml", tags=["ML"])


def _require_ml():
    from ml import ml_engine
    if ml_engine is None:
        raise HTTPException(status_code=503, detail="ML layer not initialized")
    return ml_engine


@router.get("/health")
async def ml_health(_user=Depends(get_current_user)):
    from ml import ml_engine
    from ml.feature_builder import FEATURE_SCHEMA_VERSION

    loaded = ml_engine is not None
    version = ""
    healthy = False
    if ml_engine is not None:
        version = ml_engine.model_version
        healthy = ml_engine.is_healthy()

    return {
        "model_loaded": loaded,
        "model_version": version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "inference_healthy": healthy,
    }


@router.get("/metrics")
async def ml_metrics(_user=Depends(get_current_user)):
    from ml.config import ml_config
    from ml.shadow_store import ShadowStore

    try:
        db = get_database()
    except Exception:
        return {
            "disagreement_rate_24h": 0.0,
            "total_assessments_24h": 0,
            "disagreements_24h": 0,
            "ml_override_enabled": ml_config.ML_OVERRIDE_ENABLED,
            "shadow_mode": not ml_config.ML_OVERRIDE_ENABLED,
        }

    store = ShadowStore(db)
    total, disagree = await store.count_since(since_hours=24)
    rate = disagree / total if total > 0 else 0.0

    return {
        "disagreement_rate_24h": round(rate, 4),
        "total_assessments_24h": total,
        "disagreements_24h": disagree,
        "ml_override_enabled": ml_config.ML_OVERRIDE_ENABLED,
        "shadow_mode": not ml_config.ML_OVERRIDE_ENABLED,
    }


@router.get("/disagreements")
async def ml_disagreements(limit: int = 20, _user=Depends(get_current_user)):
    from ml.shadow_store import ShadowStore

    try:
        db = get_database()
    except Exception:
        raise HTTPException(status_code=503, detail="Database not available")

    store = ShadowStore(db)
    docs = await store.get_recent_disagreements(limit=limit)
    results = []
    for d in docs:
        ea = d.get("ensemble_assessment") or {}
        ra = ea.get("rule_assessment") or {}
        ml_a = d.get("ml_assessment") or {}
        results.append({
            "component_name": d.get("component_name"),
            "rule_verdict": ra.get("quantum_status_rule"),
            "ml_verdict": {0: "QUANTUM_SAFE", 1: "PARTIALLY_SAFE", 2: "VULNERABLE"}.get(
                ml_a.get("predicted_class"), "UNKNOWN"
            ),
            "ensemble_confidence": ea.get("ensemble_confidence"),
            "ood_score": ml_a.get("ood_score"),
            "decision_path": ea.get("decision_path"),
        })
    return results


@router.get("/model-info")
async def ml_model_info(_user=Depends(get_current_user)):
    _require_ml()
    from ml.config import ml_config

    registry_path = os.path.join(
        os.path.dirname(ml_config.ML_MODEL_PATH), "registry.json"
    )
    if not os.path.isfile(registry_path):
        raise HTTPException(status_code=404, detail="Registry file not found")

    with open(registry_path, encoding="utf-8") as f:
        return json.load(f)
