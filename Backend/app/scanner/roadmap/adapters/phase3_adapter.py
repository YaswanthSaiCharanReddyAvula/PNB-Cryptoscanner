"""
Phase 3 Adapter

Bridges the gap between the CanonicalInventory (Phase 3) and the Roadmap Engine.
Extracts and normalizes context like asset criticality, data sensitivity, and exposure.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from app.scanner.convergence.canonical_models import CanonicalInventory, CanonicalAsset, CanonicalFinding

class NormalizedAssetContext(BaseModel):
    asset_id: str
    asset_type: str
    name: str
    business_criticality: str = "UNKNOWN"
    internet_exposure: str = "UNKNOWN"
    data_sensitivity: str = "UNKNOWN"
    environment: str = "UNKNOWN"
    owner: str = "UNKNOWN"
    technology: str = "UNKNOWN"
    dependencies: List[str] = Field(default_factory=list)

class NormalizedFindingContext(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    confidence: float
    state: str
    evidence: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    asset_contexts: List[NormalizedAssetContext] = Field(default_factory=list)

class Phase3Context(BaseModel):
    scan_id: str
    target: str
    findings: List[NormalizedFindingContext] = Field(default_factory=list)


def extract_property(asset: CanonicalAsset, key: str, default: str = "UNKNOWN") -> str:
    prop = asset.properties.get(key)
    if prop is None:
        return default
    if hasattr(prop, "canonical_value"):
        return str(prop.canonical_value).upper()
    return str(prop).upper()


def resolve_asset_context(asset: CanonicalAsset) -> NormalizedAssetContext:
    ctx = NormalizedAssetContext(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type),
        name=asset.name,
        business_criticality=extract_property(asset, "business_criticality"),
        internet_exposure=extract_property(asset, "internet_exposure", "INTERNAL"),
        data_sensitivity=extract_property(asset, "data_classification", "UNKNOWN"),
        environment=extract_property(asset, "environment"),
        owner=extract_property(asset, "owner"),
        technology=extract_property(asset, "technology"),
        dependencies=[rel.target_id for rel in asset.relationships if rel.type == "depends_on"]
    )
    # Special inference for exposure if not explicitly tagged but location implies it
    if ctx.internet_exposure == "UNKNOWN" and any(loc.type == "url" and "localhost" not in loc.value for loc in asset.locations):
         ctx.internet_exposure = "INTERNET_FACING"
         
    return ctx


def build_phase3_context(inventory: CanonicalInventory) -> Phase3Context:
    """Extracts finding-driven roadmap context from the Phase 3 inventory."""
    # Build a lookup for fast asset resolution
    asset_lookup: Dict[str, CanonicalAsset] = {}
    if hasattr(inventory.assets, "model_fields"):
        fields = inventory.assets.model_fields.keys()
    else:
        fields = inventory.assets.__fields__.keys()
        
    for field_name in fields:
        asset_list = getattr(inventory.assets, field_name)
        for asset in asset_list:
            asset_lookup[asset.asset_id] = asset

    findings_context = []
    
    for finding in inventory.findings:
        # Only process actionable findings (OBSERVED or INFERRED)
        if hasattr(finding.status, "value"):
            status_val = finding.status.value
        else:
            status_val = str(finding.status)
            
        if status_val not in ("OBSERVED", "INFERRED"):
            continue

        f_ctx = NormalizedFindingContext(
            finding_id=finding.finding_id,
            finding_type=finding.finding_type,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            confidence=finding.confidence,
            state=status_val,
            evidence=finding.evidence_refs,
            source=finding.source,
            asset_contexts=[]
        )
        
        for asset_id in finding.asset_refs:
            if asset_id in asset_lookup:
                f_ctx.asset_contexts.append(resolve_asset_context(asset_lookup[asset_id]))
                
        findings_context.append(f_ctx)
        
    return Phase3Context(
        scan_id=inventory.scan_id,
        target=inventory.target,
        findings=findings_context
    )
