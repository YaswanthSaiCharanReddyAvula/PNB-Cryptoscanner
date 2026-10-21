"""
Phase 4 — Quantum Risk Engine Stage
"""

from __future__ import annotations
from typing import Any

from app.scanner.pipeline import ScanStage, ScanContext, StageResult, MergeStrategy, StageCriticality
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.aggregation_engine import aggregate_asset_risk, aggregate_organization_risk
from app.utils.logger import get_logger

logger = get_logger(__name__)


class QuantumRiskStage(ScanStage):
    """
    Phase 4: Computes Quantum Risk and Migration Urgency (Mosca/HNDL)
    using the Canonical Inventory (Phase 3).
    """
    name = "quantum_risk"
    order = 32  # Track C: Runs after CBOMUnification (30) and Convergence (31)
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
        resolution_errors: dict[str, str] = {}
        canonical_assets = (
            ctx.canonical_inventory.all_assets()
            if hasattr(ctx.canonical_inventory, "all_assets")
            else (
                ctx.canonical_inventory.assets.all_assets()
                if hasattr(getattr(ctx.canonical_inventory, "assets", None), "all_assets")
                else []
            )
        )
        for asset in canonical_assets:
            try:
                asset_assessments = resolve_asset_quantum_risk(asset, scenario="baseline")
                assessments.extend(asset_assessments)
                
                summary = aggregate_asset_risk(asset.asset_id, asset_assessments)
                asset_summaries.append(summary)
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                asset_id = getattr(asset, "asset_id", "unknown")
                logger.error(
                    "[%s] Failed to resolve quantum risk for asset %s: %s",
                    ctx.scan_id,
                    asset_id,
                    err_msg,
                )
                resolution_errors[asset_id] = err_msg
                if hasattr(ctx, "errors") and isinstance(ctx.errors, list):
                    ctx.errors.append({
                        "stage": "quantum_risk",
                        "step": "resolve_asset_quantum_risk",
                        "asset_id": asset_id,
                        "error": err_msg,
                    })
            
        org_summary = aggregate_organization_risk(asset_summaries)
            
        # Optional: Save these independently to MongoDB
        write_errors: dict[str, str] = {}
        if ctx.db is not None:
            if assessments:
                assessment_docs = [a.model_dump() for a in assessments]
                # Defect D2 fix: attach scan_id so assessments are queryable by scan
                for doc in assessment_docs:
                    if not doc.get("scan_id"):
                        doc["scan_id"] = ctx.scan_id
                try:
                    await ctx.db["quantum_assessments"].insert_many(assessment_docs)
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"
                    logger.error(
                        "[%s] Failed to write quantum_assessments to database: %s",
                        ctx.scan_id,
                        err,
                    )
                    write_errors["quantum_assessments"] = err

            if asset_summaries:
                summary_docs = [s.model_dump() for s in asset_summaries]
                # Attach scan_id to summaries
                for doc in summary_docs:
                    if not doc.get("scan_id"):
                        doc["scan_id"] = ctx.scan_id
                try:
                    await ctx.db["quantum_asset_summaries"].insert_many(summary_docs)
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"
                    logger.error(
                        "[%s] Failed to write quantum_asset_summaries to database: %s",
                        ctx.scan_id,
                        err,
                    )
                    write_errors["quantum_asset_summaries"] = err
            
            org_doc = org_summary.model_dump()
            if not org_doc.get("scan_id"):
                org_doc["scan_id"] = ctx.scan_id
            try:
                await ctx.db["quantum_org_summaries"].insert_one(org_doc)
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                logger.error(
                    "[%s] Failed to write quantum_org_summaries to database: %s",
                    ctx.scan_id,
                    err,
                )
                write_errors["quantum_org_summaries"] = err

        if write_errors:
            ctx.quantum_write_errors = write_errors
        if resolution_errors:
            ctx.quantum_resolution_errors = resolution_errors

        # Check if any eligible cryptographic assessments were actually resolved
        has_crypto_assessments = len(assessments) > 0

        # Populate the final scan output explicitly
        # Persisted flag and write_errors prevent ctx.quantum_score from being interpreted
        # as proof that all database writes succeeded.
        ctx.quantum_score = {
            "score": org_summary.overall_quantum_risk_score,
            "risk_level": org_summary.risk_tier.lower() if has_crypto_assessments else "unknown",
            "confidence": org_summary.confidence if has_crypto_assessments else 0.0,
            "unknown_coverage": org_summary.unknown_coverage if has_crypto_assessments else 1.0,
            "persisted": len(write_errors) == 0 if ctx.db is not None else False,
            "write_errors": list(write_errors.keys()),
        }

        has_partial_failure = bool(write_errors or resolution_errors)
        stage_status = "partial" if has_partial_failure else "completed"

        error_parts = []
        if resolution_errors:
            error_parts.append(
                f"Quantum risk stage asset resolution failed for: {', '.join(resolution_errors.keys())}"
            )
        if write_errors:
            error_parts.append(
                f"Quantum risk stage DB write failed for: {', '.join(write_errors.keys())}"
            )
        stage_error = "; ".join(error_parts) if error_parts else None
                
        return StageResult(
            status=stage_status,
            data={
                "quantum_assessments": [a.model_dump() for a in assessments],
                "quantum_asset_summaries": [s.model_dump() for s in asset_summaries],
                "quantum_org_summary": org_summary.model_dump(),
                "write_errors": write_errors,
                "resolution_errors": resolution_errors,
            },
            error=stage_error,
        )
