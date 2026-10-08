"""
Phase 4 — Quantum Risk Engine Stage
"""

from __future__ import annotations
from typing import Any

from app.scanner.pipeline import ScanStage, ScanContext, StageResult, MergeStrategy, StageCriticality
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.aggregation_engine import aggregate_asset_risk, aggregate_organization_risk


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
        asset_summaries = []
        for asset in ctx.canonical_inventory.assets:
            asset_assessments = resolve_asset_quantum_risk(asset, scenario="baseline")
            assessments.extend(asset_assessments)
            
            summary = aggregate_asset_risk(asset.asset_id, asset_assessments)
            asset_summaries.append(summary)
            
        org_summary = aggregate_organization_risk(asset_summaries)
            
        # Optional: Save these independently to MongoDB
        if ctx.db is not None:
            if assessments:
                assessment_docs = [a.model_dump() for a in assessments]
                try:
                    await ctx.db["quantum_assessments"].insert_many(assessment_docs)
                except Exception:
                    pass
            if asset_summaries:
                summary_docs = [s.model_dump() for s in asset_summaries]
                # Attach scan_id to summaries
                for doc in summary_docs:
                    doc["scan_id"] = ctx.scan_id
                try:
                    await ctx.db["quantum_asset_summaries"].insert_many(summary_docs)
                except Exception:
                    pass
            
            org_doc = org_summary.model_dump()
            org_doc["scan_id"] = ctx.scan_id
            try:
                await ctx.db["quantum_org_summaries"].insert_one(org_doc)
            except Exception:
                pass
                
        # Populate the final scan output explicitly
        ctx.quantum_score = {
            "score": org_summary.overall_quantum_risk_score,
            "risk_level": org_summary.risk_tier.lower(),
            "confidence": org_summary.confidence,
            "unknown_coverage": org_summary.unknown_coverage
        }
                
        return StageResult(
            status="completed",
            data={
                "quantum_assessments": [a.model_dump() for a in assessments],
                "quantum_asset_summaries": [s.model_dump() for s in asset_summaries],
                "quantum_org_summary": org_summary.model_dump()
            }
        )
