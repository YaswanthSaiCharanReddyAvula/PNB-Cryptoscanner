"""
QuantumShield — Convergence Base Adapter

Base classes for engine adapters that translate engine-specific output into
the Canonical Data Model.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.pipeline import ScanContext


def extract_field(obj: Any, key: Any, default: Any = None) -> Any:
    """Safely extracts a field from a dict, Pydantic model, or arbitrary object.
    Supports a tuple or list of alternative keys to probe in sequence."""
    if obj is None:
        return default
    keys = (key,) if isinstance(key, str) else tuple(key)
    for k in keys:
        if isinstance(obj, dict):
            val = obj.get(k)
            if val is not None:
                return val
        elif hasattr(obj, str(k)):
            val = getattr(obj, str(k), None)
            if val is not None:
                return val
    return default


class EngineAdapter(ABC):
    """
    Abstract base class for all engine adapters.
    Each adapter is responsible for reading its engine's specific output
    from the ScanContext and producing CanonicalAssets, CanonicalFindings,
    and CanonicalEvidence.
    """
    
    def __init__(self):
        self.conversion_errors: List[str] = []

    def record_error(self, message: str) -> None:
        """Records a conversion failure or malformed record error."""
        self.conversion_errors.append(message)

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Name of the source engine (e.g., 'tls_engine', 'sca_engine')."""
        pass
        
    @property
    @abstractmethod
    def engine_stage(self) -> str:
        """Name of the stage this adapter processes."""
        pass

    @abstractmethod
    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        """
        Process the ScanContext and extract canonical data.
        Returns: (assets, findings, evidence)
        """
        pass
