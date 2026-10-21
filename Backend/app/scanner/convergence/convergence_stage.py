"""
QuantumShield — Convergence Stage

The central barrier that guarantees Track A, Track B, and Cloud data have
finished collecting before we begin normalization, correlation, and aggregation.
"""

from typing import List

from app.scanner.convergence.adapters import (
    CloudAdapter,
    ContainerAdapter,
    CryptoAdapter,
    NetworkAdapter,
    ReconAdapter,
    SASTAdapter,
    SCAAdapter,
    TLSAdapter,
    VulnAdapter,
)
from app.scanner.convergence.aggregation import CanonicalInventoryBuilder
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.correlation_engine import correlate_assets
from app.scanner.convergence.deduplication import deduplicate_assets, deduplicate_findings
from app.scanner.models import StageResult
from app.scanner.pipeline import MergeStrategy, ScanContext, ScanStage, StageCriticality
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ConvergenceStage(ScanStage):
    name = "convergence"
    order = 31  # Track C: Runs after CBOMUnification (30) and before QuantumRiskStage (32)
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields = [] 
    writes_fields = ["canonical_inventory"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        logger.info("Executing Convergence Barrier...")
        
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        adapter_errors: dict[str, str] = {}
        
        # 1. Run all adapters
        adapters = [
            ReconAdapter(),
            NetworkAdapter(),
            TLSAdapter(),
            CryptoAdapter(),
            VulnAdapter(),
            SASTAdapter(),
            SCAAdapter(),
            ContainerAdapter(),
            CloudAdapter()
        ]
        
        successful_adapters = 0
        for adapter in adapters:
            try:
                a, f, e = adapter.process(ctx)
                assets.extend(a)
                findings.extend(f)
                evidence.extend(e)
                successful_adapters += 1
                if hasattr(adapter, "conversion_errors") and adapter.conversion_errors:
                    adapter_errors[adapter.engine_name] = "; ".join(adapter.conversion_errors)
            except Exception as ex:
                logger.error("Adapter %s failed: %s", adapter.engine_name, ex, exc_info=True)
                adapter_errors[adapter.engine_name] = str(ex)

        # If every adapter failed catastrophically, convergence failed
        if successful_adapters == 0 and adapter_errors:
            return StageResult(
                status="error",
                error=f"Convergence failed: all adapters raised exceptions: {adapter_errors}",
                data={"adapter_errors": adapter_errors}
            )

        # 2. Deduplicate
        logger.info(f"Deduplicating {len(assets)} assets and {len(findings)} findings...")
        unique_assets = deduplicate_assets(assets)
        unique_findings = deduplicate_findings(findings)

        # 3. Correlate
        logger.info("Correlating cross-engine assets...")
        correlated_assets = correlate_assets(unique_assets)
        
        # 4. Aggregate
        logger.info("Building Canonical Inventory...")
        inventory = CanonicalInventoryBuilder.build(
            scan_id=ctx.scan_id,
            target=ctx.domain or "",
            assets=correlated_assets,
            findings=unique_findings,
            evidence=evidence
        )
        
        # Save to context
        ctx.canonical_inventory = inventory
        # Defect D3 fix: expose adapter errors on context so the persistence layer
        # can store them on the root scan document for API / dashboard observability.
        if adapter_errors:
            ctx.convergence_adapter_errors = adapter_errors

        result_data = {
            "total_assets": len(correlated_assets),
            "total_findings": len(unique_findings),
            "total_evidence": len(evidence),
            "canonical_inventory": inventory,
            "adapter_errors": adapter_errors,
        }

        # Check for partial failure state
        if adapter_errors:
            err_msg = f"Convergence completed with adapter errors in: {', '.join(adapter_errors.keys())}"
            logger.warning(err_msg)
            return StageResult(
                status="partial",
                data=result_data,
                error=err_msg
            )

        # Check for absent target data
        if not ctx.domain and not correlated_assets and not unique_findings:
            err_msg = "Convergence completed but required target domain and asset data were absent"
            logger.warning(err_msg)
            return StageResult(
                status="partial",
                data=result_data,
                error=err_msg
            )
        
        return StageResult(
            status="success",
            data=result_data
        )
