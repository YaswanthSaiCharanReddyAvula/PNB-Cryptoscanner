"""
QuantumShield — Convergence Conflict Resolution

Handles conflict resolution when different engines report conflicting observations
for the same asset or property.
"""

from typing import Any, Dict, List

from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalEvidence


class ObservationSet:
    """
    Maintains multiple conflicting observations and prioritizes them based on
    predefined rules rather than silently discarding them.
    """
    
    # Example Priority (higher index = higher priority):
    # 0: heuristic inference
    # 1: network banner
    # 2: HTTP response
    # 3: active protocol observation
    # 4: TLS certificate metadata
    # 5: authenticated cloud API
    # 6: verified structured source
    
    PRIORITY_MAP = {
        "heuristic": 0,
        "network_banner": 1,
        "http_response": 2,
        "protocol_observation": 3,
        "certificate_metadata": 4,
        "cloud_api": 5,
        "structured_source": 6
    }
    
    def __init__(self):
        self.observations: List[Dict[str, Any]] = []
        
    def add_observation(self, value: Any, source: str, priority_key: str, evidence: CanonicalEvidence):
        self.observations.append({
            "value": value,
            "source": source,
            "priority": self.PRIORITY_MAP.get(priority_key, 0),
            "evidence": evidence
        })
        
    def resolve(self) -> Any:
        """Returns the highest priority value without discarding others from evidence."""
        if not self.observations:
            return None
            
        # Sort by priority descending
        sorted_obs = sorted(self.observations, key=lambda x: x["priority"], reverse=True)
        return sorted_obs[0]["value"]


def resolve_asset_conflicts(assets: List[CanonicalAsset]) -> List[CanonicalAsset]:
    """
    Given a list of partially merged assets, resolves field-level conflicts
    using ObservationSets. Currently a placeholder for complex logic.
    """
    return assets
