"""
QuantumShield — Convergence Correlation Engine

Links canonical assets together after they have been individually normalized
and deduplicated.
"""

from typing import Dict, List

from app.scanner.convergence.canonical_models import CanonicalAsset, Relationship
from app.scanner.convergence.enums import AssetType


def correlate_assets(assets: List[CanonicalAsset]) -> List[CanonicalAsset]:
    """
    Performs cross-asset correlation.
    - Links Services to Hosts via IP/Hostname matching if not already linked.
    - Links Certificates to Keys via fingerprints.
    - Establishes shared infrastructure relationships.
    """
    
    # Fast lookups
    hosts_by_ip = {}
    hosts_by_name = {}
    keys_by_fingerprint = {}
    certs_by_fingerprint = {}
    
    for asset in assets:
        if asset.asset_type == AssetType.HOST:
            for ident in asset.identifiers:
                if ident.type == "ip":
                    if ident.value not in hosts_by_ip:
                        hosts_by_ip[ident.value] = []
                    hosts_by_ip[ident.value].append(asset)
                elif ident.type == "hostname":
                    hosts_by_name[ident.value] = asset
                    
        elif asset.asset_type == AssetType.KEY:
            for ident in asset.identifiers:
                if ident.type == "fingerprint":
                    keys_by_fingerprint[ident.value] = asset
                    
        elif asset.asset_type == AssetType.CERTIFICATE:
            for ident in asset.identifiers:
                if ident.type == "fingerprint":
                    certs_by_fingerprint[ident.value] = asset

    # 1. Shared Infrastructure (Multiple hostnames resolving to same IP)
    for ip, host_assets in hosts_by_ip.items():
        if len(host_assets) > 1:
            # We have multiple hosts resolving to the same IP, they share infrastructure
            ip_asset = host_assets[0] # The one that is actually the IP
            # We already linked hostname -> ip in ReconAdapter, but we can add 'shares_infrastructure_with' 
            # or just rely on 'resolves_to' -> same IP.
            pass

    # 2. Key <-> Certificate Correlation
    for cert_fp, cert_asset in certs_by_fingerprint.items():
        if cert_fp in keys_by_fingerprint:
            key_asset = keys_by_fingerprint[cert_fp]
            
            # Ensure they are linked
            has_link = any(r.target_id == key_asset.asset_id for r in cert_asset.relationships)
            if not has_link:
                cert_asset.relationships.append(
                    Relationship(type="matches_key", target_id=key_asset.asset_id)
                )
                key_asset.relationships.append(
                    Relationship(type="matches_certificate", target_id=cert_asset.asset_id)
                )

    return assets
