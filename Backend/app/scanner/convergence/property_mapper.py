"""
QuantumShield — Convergence Property Mapper

Handles mapping from raw scanner observations to canonical asset properties.
"""

from typing import Any, Callable, Dict, Optional
from app.scanner.convergence.canonical_models import CanonicalObservation, CanonicalProperty


class PropertyMappingRegistry:
    """
    Central registry defining how specific engine observations map to canonical properties.
    """
    
    def __init__(self):
        # Format: { "source_engine": { "source_field": ("canonical_property_name", transformer_func) } }
        self._mappings: Dict[str, Dict[str, tuple]] = {}
        
    def register(self, engine: str, source_field: str, canonical_property: str, transformer: Optional[Callable] = None):
        if engine not in self._mappings:
            self._mappings[engine] = {}
        self._mappings[engine][source_field] = (canonical_property, transformer)
        
    def get_mapping(self, engine: str, source_field: str) -> Optional[tuple]:
        return self._mappings.get(engine, {}).get(source_field)


class PropertyMapper:
    """
    Applies the registry rules to transform an observation into a CanonicalProperty (or updates an existing one).
    """
    
    def __init__(self, registry: PropertyMappingRegistry):
        self.registry = registry
        
    def map_observation(self, obs: CanonicalObservation) -> CanonicalProperty:
        """
        Maps a raw observation to a CanonicalProperty.
        If a mapping exists in the registry, it applies the transformation.
        Otherwise, it falls back to using the raw property_name and property_value.
        """
        prop_name = obs.property_name
        prop_val = obs.property_value
        
        mapping = self.registry.get_mapping(obs.source_engine, obs.property_name)
        if mapping:
            canonical_name, transformer = mapping
            prop_name = canonical_name
            if transformer:
                prop_val = transformer(prop_val)
                
        return CanonicalProperty(
            name=prop_name,
            canonical_value=prop_val,
            state=obs.state,
            confidence=obs.confidence,
            observations=[obs]
        )
