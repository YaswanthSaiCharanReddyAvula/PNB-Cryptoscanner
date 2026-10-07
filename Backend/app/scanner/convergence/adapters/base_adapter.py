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


class EngineAdapter(ABC):
    """
    Abstract base class for all engine adapters.
    Each adapter is responsible for reading its engine's specific output
    from the ScanContext and producing CanonicalAssets, CanonicalFindings,
    and CanonicalEvidence.
    """
    
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
