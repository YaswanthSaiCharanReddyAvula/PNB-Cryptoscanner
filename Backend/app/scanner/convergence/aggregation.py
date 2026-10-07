"""
QuantumShield — Convergence Aggregation

Consolidates all canonical data into a single, deterministically ordered
Estate model representing the entire scanned infrastructure.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.enums import AssetType


class EstateAssets(BaseModel):
    hosts: List[CanonicalAsset] = Field(default_factory=list)
    services: List[CanonicalAsset] = Field(default_factory=list)
    technologies: List[CanonicalAsset] = Field(default_factory=list)
    packages: List[CanonicalAsset] = Field(default_factory=list)
    containers: List[CanonicalAsset] = Field(default_factory=list)
    certificates: List[CanonicalAsset] = Field(default_factory=list)
    keys: List[CanonicalAsset] = Field(default_factory=list)
    algorithms: List[CanonicalAsset] = Field(default_factory=list)
    cloud_resources: List[CanonicalAsset] = Field(default_factory=list)
    protocols: List[CanonicalAsset] = Field(default_factory=list)
    other: List[CanonicalAsset] = Field(default_factory=list)


class CanonicalEstate(BaseModel):
    scan_id: str
    target: str
    assets: EstateAssets = Field(default_factory=EstateAssets)
    findings: List[CanonicalFinding] = Field(default_factory=list)
    evidence: List[CanonicalEvidence] = Field(default_factory=list)


def aggregate_estate(
    scan_id: str,
    target: str,
    assets: List[CanonicalAsset],
    findings: List[CanonicalFinding],
    evidence: List[CanonicalEvidence]
) -> CanonicalEstate:
    """
    Aggregates and deterministically sorts all canonical data into the CanonicalEstate.
    """
    estate = CanonicalEstate(scan_id=scan_id, target=target)
    
    # Sort evidence by ID
    estate.evidence = sorted(evidence, key=lambda e: e.evidence_id)
    
    # Sort findings by ID
    estate.findings = sorted(findings, key=lambda f: f.finding_id)
    
    # Categorize and sort assets
    for asset in sorted(assets, key=lambda a: a.asset_id):
        if asset.asset_type == AssetType.HOST:
            estate.assets.hosts.append(asset)
        elif asset.asset_type == AssetType.SERVICE:
            estate.assets.services.append(asset)
        elif asset.asset_type in (AssetType.FRAMEWORK, AssetType.LIBRARY, AssetType.APPLICATION):
            estate.assets.technologies.append(asset)
        elif asset.asset_type == AssetType.PACKAGE:
            estate.assets.packages.append(asset)
        elif asset.asset_type == AssetType.CONTAINER:
            estate.assets.containers.append(asset)
        elif asset.asset_type == AssetType.CERTIFICATE:
            estate.assets.certificates.append(asset)
        elif asset.asset_type == AssetType.KEY:
            estate.assets.keys.append(asset)
        elif asset.asset_type == AssetType.ALGORITHM:
            estate.assets.algorithms.append(asset)
        elif asset.asset_type == AssetType.CLOUD_RESOURCE:
            estate.assets.cloud_resources.append(asset)
        elif asset.asset_type == AssetType.PROTOCOL:
            estate.assets.protocols.append(asset)
        else:
            estate.assets.other.append(asset)
            
    return estate
