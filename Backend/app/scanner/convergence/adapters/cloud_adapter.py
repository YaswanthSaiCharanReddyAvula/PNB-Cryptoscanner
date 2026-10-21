"""
QuantumShield — Convergence Cloud Adapter

Transforms cloud crypto assets into canonical models.
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


class CloudAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "cloud_audit"

    @property
    def engine_stage(self) -> str:
        return "source/cloud"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        # Cloud assets might be stored in ctx.cloud_crypto_assets or ctx.cloud_assets
        cloud_assets_raw = getattr(ctx, "cloud_crypto_assets", []) or getattr(ctx, "cloud_assets", [])
        
        for cloud_asset in cloud_assets_raw:
            if not isinstance(cloud_asset, dict) and not hasattr(cloud_asset, "resource_id") and not hasattr(cloud_asset, "id"):
                msg = f"Skipping malformed cloud asset record: invalid type {type(cloud_asset).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            provider = extract_field(cloud_asset, "provider", "unknown_cloud")
            resource_id = extract_field(cloud_asset, ("resource_id", "id"))
            if not resource_id:
                msg = f"Skipping cloud asset missing resource_id/id: {cloud_asset!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            region = extract_field(cloud_asset, "region", "unknown_region")
            name = extract_field(cloud_asset, "name", str(resource_id))
            
            # Identify if it's a key or just a general cloud resource
            asset_type = AssetType.CLOUD_RESOURCE
            asset_type_str = str(extract_field(cloud_asset, "asset_type", "cloud_resource")).lower()
            if "key" in asset_type_str or "kms" in asset_type_str:
                asset_type = AssetType.KEY
                
            properties = {
                "provider": provider,
                "region": region,
                "account": extract_field(cloud_asset, ("account", "project")),
                "crypto_properties": extract_field(cloud_asset, "crypto_properties", {})
            }
            
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=asset_type,
                name=str(name),
                identifiers=[Identifier(type="cloud_resource_id", value=str(resource_id))],
                locations=[Location(type="cloud_region", value=f"{provider}:{region}")],
                properties=properties,
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(asset)
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="cloud_api_discovery",
                target=str(resource_id),
                observed_at=now,
                value=f"Cloud Asset: {provider} - {region}"
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)
            
        return assets, findings, evidence
