"""
Shadow store: persist ML assessments alongside the rule engine output.

Writes to a dedicated ``ml_assessments`` MongoDB collection. All writes are
fire-and-forget — failures are logged but never block the scan pipeline.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ml.ensemble import EnsembleAssessment, RuleAssessment
from ml.inference_engine import MLAssessment


ML_ASSESSMENTS_COLLECTION = "ml_assessments"


def _component_hash(name: str, category: str, key_size: Any, host: str) -> str:
    raw = f"{name}|{category}|{key_size}|{host}"
    return hashlib.md5(raw.encode()).hexdigest()


class ShadowStore:
    def __init__(self, db: Any) -> None:
        self._db = db

    async def save(
        self,
        scan_id: str,
        component_name: str,
        component_category: str,
        component_key_size: Any,
        component_host: str,
        ml_assessment: MLAssessment,
        ensemble_assessment: EnsembleAssessment,
    ) -> None:
        doc = {
            "scan_id": scan_id,
            "component_hash": _component_hash(
                component_name, component_category,
                component_key_size, component_host,
            ),
            "component_name": component_name,
            "ml_assessment": ml_assessment.model_dump(),
            "ensemble_assessment": ensemble_assessment.model_dump(),
            "disagreement": ensemble_assessment.disagreement,
            "created_at": datetime.now(timezone.utc),
        }
        await self._db[ML_ASSESSMENTS_COLLECTION].insert_one(doc)

    async def get_disagreements(
        self, scan_id: str, limit: int = 50,
    ) -> List[Dict[str, Any]]:
        cursor = (
            self._db[ML_ASSESSMENTS_COLLECTION]
            .find({"scan_id": scan_id, "disagreement": True})
            .sort("created_at", -1)
            .limit(limit)
        )
        return [doc async for doc in cursor]

    async def get_disagreement_rate(self, since_hours: int = 24) -> float:
        cutoff = datetime.now(timezone.utc).timestamp() - since_hours * 3600
        from datetime import datetime as dt

        cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)
        total = await self._db[ML_ASSESSMENTS_COLLECTION].count_documents(
            {"created_at": {"$gte": cutoff_dt}}
        )
        if total == 0:
            return 0.0
        disagree = await self._db[ML_ASSESSMENTS_COLLECTION].count_documents(
            {"created_at": {"$gte": cutoff_dt}, "disagreement": True}
        )
        return disagree / total

    async def get_recent_disagreements(self, limit: int = 20) -> List[Dict[str, Any]]:
        cursor = (
            self._db[ML_ASSESSMENTS_COLLECTION]
            .find({"disagreement": True})
            .sort("created_at", -1)
            .limit(limit)
        )
        results: List[Dict[str, Any]] = []
        async for doc in cursor:
            doc.pop("_id", None)
            results.append(doc)
        return results

    async def count_since(self, since_hours: int = 24) -> tuple[int, int]:
        cutoff = datetime.now(timezone.utc).timestamp() - since_hours * 3600
        cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)
        total = await self._db[ML_ASSESSMENTS_COLLECTION].count_documents(
            {"created_at": {"$gte": cutoff_dt}}
        )
        disagree = await self._db[ML_ASSESSMENTS_COLLECTION].count_documents(
            {"created_at": {"$gte": cutoff_dt}, "disagreement": True}
        )
        return total, disagree
