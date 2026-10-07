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
from app.scanner.convergence.aggregation import aggregate_estate
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
    order = 10  # Before correlation (11) and reporting (12)
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.CRITICAL
    required_fields = [] 
    writes_fields = ["canonical_inventory"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        logger.info("Executing Convergence Barrier...")
        
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
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
        
        for adapter in adapters:
            try:
                a, f, e = adapter.process(ctx)
                assets.extend(a)
                findings.extend(f)
                evidence.extend(e)
            except Exception as ex:
                logger.error(f"Adapter {adapter.engine_name} failed: {ex}")
                # We do not fail the whole scan if one adapter errors, partial failure handling.

        # 2. Deduplicate
        logger.info(f"Deduplicating {len(assets)} assets and {len(findings)} findings...")
        unique_assets = deduplicate_assets(assets)
        unique_findings = deduplicate_findings(findings)

        # 3. Correlate
        logger.info("Correlating cross-engine assets...")
        correlated_assets = correlate_assets(unique_assets)
        
        # 4. Aggregate
        logger.info("Aggregating Canonical Estate...")
        estate = aggregate_estate(
            scan_id=ctx.scan_id,
            target=ctx.domain,
            assets=correlated_assets,
            findings=unique_findings,
            evidence=evidence
        )
        
        # Save to context
        ctx.canonical_inventory = estate
        
        return StageResult(
            status="success",
            data={
                "total_assets": len(correlated_assets),
                "total_findings": len(unique_findings),
                "total_evidence": len(evidence)
            }
        )
