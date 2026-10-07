"""
QuantumShield — Convergence Deduplication

Centralized deduplication engine for CanonicalFindings and CanonicalAssets.
"""

from typing import Dict, List, Set, Tuple

from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalFinding
from app.scanner.convergence.enums import AssetType


def _generate_finding_identity(finding: CanonicalFinding) -> str:
    """
    Generates a deterministic identity for a finding.
    Identity = finding_type + asset_refs (sorted) + vulnerability_id + crypto_params.
    """
    parts = [finding.finding_type]
    
    # Sort asset refs to ensure consistency
    parts.append(",".join(sorted(finding.asset_refs)))
    
    if "vulnerability_id" in finding.details:
        parts.append(str(finding.details["vulnerability_id"]))
        
    if finding.finding_type == "crypto_finding":
        alg = finding.details.get("algorithm", "")
        parts.append(str(alg))
        
    return "|".join(parts)


def deduplicate_findings(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    """
    Deduplicates findings based on their generated identity.
    Merges sources and evidence_refs from duplicate findings into the primary one.
    """
    unique_findings: Dict[str, CanonicalFinding] = {}
    
    for finding in findings:
        identity = _generate_finding_identity(finding)
        
        if identity in unique_findings:
            # Merge sources and evidence
            existing = unique_findings[identity]
            existing.source = list(set(existing.source + finding.source))
            existing.evidence_refs = list(set(existing.evidence_refs + finding.evidence_refs))
            # Potentially resolve conflicting confidence/severity here
        else:
            unique_findings[identity] = finding
            
    return list(unique_findings.values())


def _generate_asset_identity(asset: CanonicalAsset) -> str:
    """
    Generates a deterministic identity for an asset based on its identifiers.
    """
    # Sort identifiers by type and value
    id_strings = sorted([f"{i.type}:{i.value}" for i in asset.identifiers])
    return f"{asset.asset_type.value}|{','.join(id_strings)}"


def deduplicate_assets(assets: List[CanonicalAsset]) -> List[CanonicalAsset]:
    """
    Deduplicates assets. Merges sources, evidence_refs, locations, and relationships.
    """
    unique_assets: Dict[str, CanonicalAsset] = {}
    
    for asset in assets:
        # If an asset has no identifiers, we fallback to its name + type
        if not asset.identifiers:
            identity = f"{asset.asset_type.value}|name:{asset.name}"
        else:
            identity = _generate_asset_identity(asset)
            
        if identity in unique_assets:
            existing = unique_assets[identity]
            existing.sources = list(set(existing.sources + asset.sources))
            existing.evidence_refs = list(set(existing.evidence_refs + asset.evidence_refs))
            
            # Merge locations uniquely
            existing_locs = {f"{l.type}:{l.value}" for l in existing.locations}
            for loc in asset.locations:
                loc_key = f"{loc.type}:{loc.value}"
                if loc_key not in existing_locs:
                    existing.locations.append(loc)
                    existing_locs.add(loc_key)
                    
            # Merge relationships uniquely
            existing_rels = {f"{r.type}:{r.target_id}" for r in existing.relationships}
            for rel in asset.relationships:
                rel_key = f"{rel.type}:{rel.target_id}"
                if rel_key not in existing_rels:
                    existing.relationships.append(rel)
                    existing_rels.add(rel_key)
                    
            # Properties could be merged recursively here
            existing.properties.update(asset.properties)
        else:
            unique_assets[identity] = asset
            
    return list(unique_assets.values())
