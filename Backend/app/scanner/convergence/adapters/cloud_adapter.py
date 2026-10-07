"""
QuantumShield — Convergence Cloud Adapter

Transforms cloud crypto assets into canonical models.
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
            # We assume cloud_asset has fields like provider, resource_id, region, crypto_properties
            provider = getattr(cloud_asset, "provider", "unknown_cloud")
            resource_id = getattr(cloud_asset, "resource_id", getattr(cloud_asset, "id", "unknown_id"))
            region = getattr(cloud_asset, "region", "unknown_region")
            name = getattr(cloud_asset, "name", resource_id)
            
            # Identify if it's a key or just a general cloud resource
            asset_type = AssetType.CLOUD_RESOURCE
            asset_type_str = getattr(cloud_asset, "asset_type", "cloud_resource").lower()
            if "key" in asset_type_str or "kms" in asset_type_str:
                asset_type = AssetType.KEY
                
            properties = {
                "provider": provider,
                "region": region,
                "account": getattr(cloud_asset, "account", getattr(cloud_asset, "project", None)),
                "crypto_properties": getattr(cloud_asset, "crypto_properties", {})
            }
            
            asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=asset_type,
                name=name,
                identifiers=[Identifier(type="cloud_resource_id", value=resource_id)],
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
                target=resource_id,
                observed_at=now,
                value=f"Cloud Asset: {provider} - {region}"
            )
            evidence.append(ev)
            asset.evidence_refs.append(ev.evidence_id)
            
        return assets, findings, evidence
