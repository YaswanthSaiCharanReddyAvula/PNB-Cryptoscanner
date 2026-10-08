from typing import Any, Dict, List, Optional
from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalProperty, CanonicalObservation


class PropertyResolutionEngine:
    """
    Resolves conflicts between multiple observations of the same property,
    preserving the conflicting observations and choosing a canonical value based on priority.
    """
    
    # Priority map for resolving conflicting properties (higher is better)
    PRIORITY_MAP = {
        "heuristic": 0,
        "network_banner": 1,
        "http_response": 2,
        "protocol_observation": 3,
        "certificate_metadata": 4,
        "cloud_api": 5,
        "structured_source": 6
    }
    
    @classmethod
    def get_source_priority(cls, source_engine: str) -> int:
        """Returns the priority of a source engine. Extensible as needed."""
        # This is a naive implementation; in reality, you might map engine names to priority categories.
        # Default priority is 0 (lowest)
        return 0
    
    @classmethod
    def resolve_property(cls, existing_prop: CanonicalProperty, new_prop: CanonicalProperty) -> CanonicalProperty:
        """
        Merges two CanonicalProperties non-destructively.
        Adds the observations from new_prop to existing_prop and recalculates the canonical_value.
        """
        if existing_prop.canonical_value == new_prop.canonical_value:
            # Same value, just add observations and possibly boost confidence
            existing_prop.observations.extend(new_prop.observations)
            existing_prop.confidence = min(1.0, existing_prop.confidence + 0.1) # Naive confidence boost
            return existing_prop
            
        # Conflict exists
        # Merge observations
        merged_observations = existing_prop.observations + new_prop.observations
        
        # Decide canonical value (naive implementation: highest priority, tie-break by recency)
        best_obs = cls._select_best_observation(merged_observations)
        
        return CanonicalProperty(
            name=existing_prop.name,
            canonical_value=best_obs.property_value if best_obs else existing_prop.canonical_value,
            value_type=existing_prop.value_type or new_prop.value_type,
            state=best_obs.state if best_obs else existing_prop.state,
            confidence=best_obs.confidence if best_obs else existing_prop.confidence,
            observations=merged_observations
        )
        
    @classmethod
    def _select_best_observation(cls, observations: List[CanonicalObservation]) -> Optional[CanonicalObservation]:
        if not observations:
            return None
            
        # Sort by (priority descending, observed_at descending)
        return sorted(
            observations,
            key=lambda obs: (cls.get_source_priority(obs.source_engine), obs.observed_at),
            reverse=True
        )[0]


def resolve_asset_conflicts(assets: List[CanonicalAsset]) -> List[CanonicalAsset]:
    """
    Placeholder for resolving complex asset-level conflicts after property-level resolution.
    Property-level conflicts are now handled in deduplication via PropertyResolutionEngine.
    """
    return assets
