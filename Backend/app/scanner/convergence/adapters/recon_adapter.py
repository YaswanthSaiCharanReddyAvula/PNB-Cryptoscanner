"""
QuantumShield — Convergence Recon Adapter

Transforms reconnaissance data (IPs, subdomains, DNS) into canonical models.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
    Relationship,
)
from app.scanner.convergence.enums import AssetType
from app.scanner.convergence.normalizers import normalize_hostname, normalize_ip
from app.scanner.pipeline import ScanContext


class ReconAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "recon_engine"

    @property
    def engine_stage(self) -> str:
        return "discovery/recon"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)
        
        # Track created assets by identity to avoid duplicating in this stage
        host_assets = {}
        ip_assets = {}

        # 1. Base Domain as an Asset
        if ctx.domain:
            norm_domain = normalize_hostname(ctx.domain)
            domain_asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.HOST,
                name=norm_domain,
                identifiers=[Identifier(type="hostname", value=norm_domain)],
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(domain_asset)
            host_assets[norm_domain] = domain_asset.asset_id

        # 2. Subdomains
        for sub in getattr(ctx, "subdomains", []):
            # sub could be a string or a dict
            sub_name = sub.get("subdomain") if isinstance(sub, dict) else sub
            norm_sub = normalize_hostname(sub_name)
            if not norm_sub or norm_sub in host_assets:
                continue
                
            sub_asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.HOST,
                name=norm_sub,
                identifiers=[Identifier(type="hostname", value=norm_sub)],
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(sub_asset)
            host_assets[norm_sub] = sub_asset.asset_id
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="subdomain_discovery",
                target=norm_sub,
                observed_at=now,
                value=norm_sub
            )
            evidence.append(ev)
            sub_asset.evidence_refs.append(ev.evidence_id)

        # 3. IP Mapping
        for host, ips in getattr(ctx, "ip_map", {}).items():
            norm_host = normalize_hostname(host)
            host_id = host_assets.get(norm_host)
            
            if not host_id:
                # If for some reason we have an IP map for a host we haven't seen in subdomains
                ha = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.HOST,
                    name=norm_host,
                    identifiers=[Identifier(type="hostname", value=norm_host)],
                    observed_at=now,
                    sources=[self.engine_name]
                )
                assets.append(ha)
                host_id = ha.asset_id
                host_assets[norm_host] = host_id
                
            for ip in ips:
                norm_ip = normalize_ip(ip)
                if not norm_ip:
                    continue
                    
                ip_id = ip_assets.get(norm_ip)
                if not ip_id:
                    ia = CanonicalAsset(
                        scan_id=ctx.scan_id,
                        asset_type=AssetType.HOST,
                        name=norm_ip,
                        identifiers=[Identifier(type="ip", value=norm_ip)],
                        observed_at=now,
                        sources=[self.engine_name]
                    )
                    assets.append(ia)
                    ip_id = ia.asset_id
                    ip_assets[norm_ip] = ip_id
                    
                # Link Hostname -> IP
                # We do this directly here since we have the mapping
                for existing_asset in assets:
                    if existing_asset.asset_id == host_id:
                        existing_asset.relationships.append(
                            Relationship(type="resolves_to", target_id=ip_id)
                        )
                        
                ev = CanonicalEvidence(
                    scan_id=ctx.scan_id,
                    source_engine=self.engine_name,
                    source_stage=self.engine_stage,
                    observation_type="dns_resolution",
                    target=norm_host,
                    observed_at=now,
                    value=norm_ip
                )
                evidence.append(ev)
                
        return assets, findings, evidence
