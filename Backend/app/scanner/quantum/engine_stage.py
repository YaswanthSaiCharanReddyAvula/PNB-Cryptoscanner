"""
Phase 4 — Quantum Risk Engine Stage
"""

from __future__ import annotations
from typing import Any

from app.scanner.pipeline import ScanStage, ScanContext, StageResult, MergeStrategy, StageCriticality
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk


class QuantumRiskStage(ScanStage):
    """
    Phase 4: Computes Quantum Risk and Migration Urgency (Mosca/HNDL)
    using the Canonical Inventory (Phase 3).
    """
    name = "quantum_risk"
    order = 13  # Runs after correlation/convergence (Phase 3)
    timeout_seconds = 30
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields = ["canonical_inventory"]
    writes_fields = ["quantum_assessments"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        if not ctx.canonical_inventory:
            return StageResult(
                status="skipped",
                error="No canonical inventory found from Phase 3."
            )
            
        assessments = []
        for asset in ctx.canonical_inventory.assets:
            asset_assessments = resolve_asset_quantum_risk(asset, scenario="baseline")
            assessments.extend(asset_assessments)
            
        # Optional: Save these independently to MongoDB
        if ctx.db is not None and assessments:
            assessment_docs = [a.model_dump() for a in assessments]
            try:
                await ctx.db["quantum_assessments"].insert_many(assessment_docs)
            except Exception as e:
                # Log but do not fail the scan entirely
                pass
                
        return StageResult(
            status="completed",
            data={"quantum_assessments": [a.model_dump() for a in assessments]}
        )
