"""
QuantumShield — CycloneDX Component Mapper

Maps CanonicalAsset objects to CycloneDX 1.6 Components.
"""

from typing import List, Optional
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import ExternalReference, ExternalReferenceType
from cyclonedx.model.crypto import CryptoProperties

from app.scanner.convergence.canonical_models import CanonicalAsset, Identifier
from app.scanner.convergence.enums import AssetType


def _map_asset_type_to_cdx_type(asset_type: AssetType) -> ComponentType:
    mapping = {
        AssetType.APPLICATION: ComponentType.APPLICATION,
        AssetType.LIBRARY: ComponentType.LIBRARY,
        AssetType.FRAMEWORK: ComponentType.FRAMEWORK,
        AssetType.CONTAINER: ComponentType.CONTAINER,
        AssetType.HOST: ComponentType.OPERATING_SYSTEM,  # Or device, but OS is typical for hosts
        AssetType.PACKAGE: ComponentType.LIBRARY,
        AssetType.CRYPTOGRAPHIC_ASSET: ComponentType.CRYPTOGRAPHIC_ASSET,
        AssetType.ALGORITHM: ComponentType.CRYPTOGRAPHIC_ASSET,
        AssetType.CERTIFICATE: ComponentType.CRYPTOGRAPHIC_ASSET,
        AssetType.KEY: ComponentType.CRYPTOGRAPHIC_ASSET,
        AssetType.PROTOCOL: ComponentType.CRYPTOGRAPHIC_ASSET,
    }
    return mapping.get(asset_type, ComponentType.LIBRARY)


def _get_identifier(identifiers: List[Identifier], id_type: str) -> Optional[str]:
    for ident in identifiers:
        if ident.type == id_type:
            return ident.value
    return None


def map_asset_to_component(asset: CanonicalAsset) -> Component:
    """
    Transforms a CanonicalAsset into a CycloneDX Component.
    """
    c_type = _map_asset_type_to_cdx_type(asset.asset_type)
    
    # We use the asset_id as the bom-ref for deterministic linkage
    bom_ref = asset.asset_id
    
    purl = _get_identifier(asset.identifiers, "purl")
    cpe = _get_identifier(asset.identifiers, "cpe")
    
    version = asset.version or "unknown"
    
    component = Component(
        type=c_type,
        name=asset.name,
        version=version,
        bom_ref=bom_ref,
        purl=purl,
        cpe=cpe,
        author=asset.vendor,
        publisher=asset.vendor,
    )

    # Hashes, e.g., container digests
    digest = _get_identifier(asset.identifiers, "digest")
    if digest:
        # Assuming SHA-256 for typical container digests
        # the cyclonedx lib expects HashAlgorithm and hash value
        try:
            from cyclonedx.model import HashAlgorithm, HashType
            if digest.startswith("sha256:"):
                component.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=digest.split(":")[1]))
        except Exception:
            pass
            
    # Crypto properties (handled centrally or here)
    if asset.asset_type in (AssetType.ALGORITHM, AssetType.CERTIFICATE, AssetType.KEY, AssetType.PROTOCOL):
        # We will populate crypto_properties via crypto_mapper.py, but we set the basic shell here
        pass

    return component
