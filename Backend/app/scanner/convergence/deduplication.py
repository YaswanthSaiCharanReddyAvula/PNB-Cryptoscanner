"""
QuantumShield — Convergence Deduplication

Centralized deduplication engine for CanonicalFindings and CanonicalAssets.
"""

from typing import Dict, List, Set, Tuple

from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalFinding, CanonicalProperty
from app.scanner.convergence.enums import AssetType
from app.scanner.convergence.identity_resolver import AssetIdentityResolver
from app.scanner.convergence.conflict_resolution import PropertyResolutionEngine


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





def deduplicate_assets(assets: List[CanonicalAsset]) -> List[CanonicalAsset]:
    """
    Deduplicates assets. Merges sources, evidence_refs, locations, and relationships.
    """
    unique_assets: Dict[str, CanonicalAsset] = {}
    
    for asset in assets:
        identity = AssetIdentityResolver.resolve_identity(asset.asset_type, asset.identifiers, asset.name)
            
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
                    
            # Properties are resolved via PropertyResolutionEngine if they are CanonicalProperties
            for prop_key, prop_val in asset.properties.items():
                if prop_key in existing.properties:
                    existing_val = existing.properties[prop_key]
                    if isinstance(existing_val, CanonicalProperty) and isinstance(prop_val, CanonicalProperty):
                        existing.properties[prop_key] = PropertyResolutionEngine.resolve_property(existing_val, prop_val)
                    else:
                        # Fallback for non-migrated properties (shallow overwrite)
                        existing.properties[prop_key] = prop_val
                else:
                    existing.properties[prop_key] = prop_val
        else:
            unique_assets[identity] = asset
            
    return list(unique_assets.values())
