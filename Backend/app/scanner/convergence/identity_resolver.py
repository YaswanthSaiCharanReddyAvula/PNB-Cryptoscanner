"""
QuantumShield — Asset Identity Resolver

Determines which real-world canonical asset an observation or set of identifiers belongs to.
Ensures deterministic, stable identities for assets to prevent duplication and collisions.
"""

from typing import List
from app.scanner.convergence.canonical_models import Identifier
from app.scanner.convergence.enums import AssetType


class AssetIdentityResolver:
    """
    Central service for resolving asset identity based on its type and identifiers.
    """

    @classmethod
    def resolve_identity(cls, asset_type: AssetType, identifiers: List[Identifier], fallback_name: str = "") -> str:
        """
        Generates a deterministic identity string for an asset.
        Identity = {asset_type}|{sorted_identifiers}
        """
        if not identifiers:
            return f"{asset_type.value}|name:{fallback_name}"

        # Sort identifiers by type and value to ensure consistent identity string
        id_strings = sorted([f"{i.type}:{i.value}" for i in identifiers])
        return f"{asset_type.value}|{','.join(id_strings)}"
