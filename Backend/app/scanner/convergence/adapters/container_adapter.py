"""
QuantumShield — Convergence Container Adapter

Transforms container assets and findings into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
)
from app.scanner.convergence.enums import AssetType
from app.scanner.pipeline import ScanContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


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
            if not isinstance(container, dict) and not hasattr(container, "image_name"):
                msg = f"Skipping malformed container record: invalid type {type(container).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            name = extract_field(container, ("image_name", "name"))
            if not name or not isinstance(name, str) or not name.strip():
                msg = f"Skipping container record missing valid image_name: {container!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            name = name.strip()
            digest = extract_field(container, "digest")
            tag = extract_field(container, "tag")
            
            identifiers = []
            if digest:
                identifiers.append(Identifier(type="digest", value=str(digest)))
                
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.CONTAINER,
                name=name,
                version=str(tag) if tag is not None else None,
                identifiers=identifiers,
                properties={
                    "architecture": extract_field(container, "architecture"),
                    "os": extract_field(container, "os"),
                    "layers": extract_field(container, "layers", [])
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
                value=str(digest or tag or name)
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)

        return assets, findings, evidence
