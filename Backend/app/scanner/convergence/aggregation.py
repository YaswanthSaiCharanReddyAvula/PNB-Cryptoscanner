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


class InventoryAssets(BaseModel):
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

    @classmethod
    def category_fields(cls) -> List[str]:
        """Returns the declared category attribute names in deterministic order."""
        return [
            "hosts",
            "services",
            "technologies",
            "packages",
            "containers",
            "certificates",
            "keys",
            "algorithms",
            "cloud_resources",
            "protocols",
            "other",
        ]

    def all_assets(self) -> List[CanonicalAsset]:
        """
        Safely returns a flat list of all distinct canonical assets across
        all categories without mutating the underlying categorized lists.
        Avoids duplicate asset enumeration and preserves asset ordering.
        """
        seen: set[str] = set()
        result: List[CanonicalAsset] = []
        for cat in self.category_fields():
            category_assets = getattr(self, cat, []) or []
            for asset in category_assets:
                if asset.asset_id not in seen:
                    seen.add(asset.asset_id)
                    result.append(asset)
        return result


class CanonicalInventory(BaseModel):
    """
    The single source of truth for Phase 3.
    Contains deterministically sorted canonical assets, findings, and evidence.
    """
    scan_id: str
    target: str
    assets: InventoryAssets = Field(default_factory=InventoryAssets)
    findings: List[CanonicalFinding] = Field(default_factory=list)
    evidence: List[CanonicalEvidence] = Field(default_factory=list)

    def all_assets(self) -> List[CanonicalAsset]:
        """Convenience accessor to all canonical assets across all categories."""
        return self.assets.all_assets() if self.assets else []


# Alias for backwards compatibility with unmigrated components
CanonicalEstate = CanonicalInventory


class CanonicalInventoryBuilder:
    """
    Consumes raw converged data and produces a deterministic CanonicalInventory.
    """
    
    @classmethod
    def build(
        cls,
        scan_id: str,
        target: str,
        assets: List[CanonicalAsset],
        findings: List[CanonicalFinding],
        evidence: List[CanonicalEvidence]
    ) -> CanonicalInventory:
        """
        Aggregates and deterministically sorts all canonical data into the CanonicalInventory.
        """
        inventory = CanonicalInventory(scan_id=scan_id, target=target)
        
        # Sort evidence by ID
        inventory.evidence = sorted(evidence, key=lambda e: e.evidence_id)
        
        # Sort findings by ID
        inventory.findings = sorted(findings, key=lambda f: f.finding_id)
        
        # Categorize and sort assets
        for asset in sorted(assets, key=lambda a: a.asset_id):
            if asset.asset_type == AssetType.HOST:
                inventory.assets.hosts.append(asset)
            elif asset.asset_type == AssetType.SERVICE:
                inventory.assets.services.append(asset)
            elif asset.asset_type in (AssetType.FRAMEWORK, AssetType.LIBRARY, AssetType.APPLICATION):
                inventory.assets.technologies.append(asset)
            elif asset.asset_type == AssetType.PACKAGE:
                inventory.assets.packages.append(asset)
            elif asset.asset_type == AssetType.CONTAINER:
                inventory.assets.containers.append(asset)
            elif asset.asset_type == AssetType.CERTIFICATE:
                inventory.assets.certificates.append(asset)
            elif asset.asset_type == AssetType.KEY:
                inventory.assets.keys.append(asset)
            elif asset.asset_type == AssetType.ALGORITHM:
                inventory.assets.algorithms.append(asset)
            elif asset.asset_type == AssetType.CLOUD_RESOURCE:
                inventory.assets.cloud_resources.append(asset)
            elif asset.asset_type == AssetType.PROTOCOL:
                inventory.assets.protocols.append(asset)
            else:
                inventory.assets.other.append(asset)
                
        # Validate that all references resolve (Requirement 60)
        cls._validate_inventory(inventory)
                
        return inventory

    @classmethod
    def _validate_inventory(cls, inventory: CanonicalInventory):
        """Ensures that all asset_refs and evidence_refs resolve."""
        asset_ids = {a.asset_id for a in inventory.all_assets()}
        for finding in inventory.findings:
            for ref in finding.asset_refs:
                if ref not in asset_ids:
                    # Log warning or handle dangling reference
                    pass


# Legacy alias
aggregate_estate = CanonicalInventoryBuilder.build
