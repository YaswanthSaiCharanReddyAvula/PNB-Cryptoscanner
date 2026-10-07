"""
QuantumShield — Convergence Container Adapter

Transforms container assets and findings into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
)
from app.scanner.convergence.enums import AssetType
from app.scanner.pipeline import ScanContext


class ContainerAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "container_scanner"

    @property
    def engine_stage(self) -> str:
        return "source/container"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        for container in getattr(ctx, "container_findings", []):
            name = getattr(container, "image_name", "unknown_container")
            digest = getattr(container, "digest", None)
            
            identifiers = []
            if digest:
                identifiers.append(Identifier(type="digest", value=digest))
                
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.CONTAINER,
                name=name,
                version=getattr(container, "tag", None),
                identifiers=identifiers,
                properties={
                    "architecture": getattr(container, "architecture", None),
                    "os": getattr(container, "os", None),
                    "layers": getattr(container, "layers", [])
                },
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(asset)
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="container_discovery",
                target=name,
                observed_at=now,
                value=digest
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)

        return assets, findings, evidence
