from typing import Optional

from cyclonedx.model.crypto import (
    CryptoProperties,
    AlgorithmProperties,
    CertificateProperties,
    ProtocolProperties,
    RelatedCryptoMaterialProperties,
    CryptoAssetType,
    ProtocolPropertiesType
)
from cyclonedx.model.component import Component

from app.scanner.convergence.canonical_models import CanonicalAsset
from app.scanner.convergence.enums import AssetType


def _map_algorithm(asset: CanonicalAsset) -> Optional[CryptoProperties]:
    props = asset.properties
    
    # Try to map to CryptoProperties algorithm properties
    algo_props = AlgorithmProperties()
    
    primitive = props.get("primitive")
    if primitive:
        # Standardize primitive string for CycloneDX if needed
        # Fallback to general assignment if enums aren't strictly required
        pass
        
    mode = props.get("mode")
    if mode:
        algo_props.mode = mode
        
    padding = props.get("padding")
    if padding:
        algo_props.padding = padding
        
    # Using asset name as the algorithm identifier
    crypto_props = CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=algo_props
    )
    return crypto_props


from datetime import datetime

def _map_certificate(asset: CanonicalAsset) -> Optional[CryptoProperties]:
    props = asset.properties
    
    def _parse_dt(dt_str):
        if not dt_str:
            return None
        if isinstance(dt_str, datetime):
            return dt_str
        try:
            # handle 'Z'
            if dt_str.endswith('Z'):
                dt_str = dt_str[:-1] + '+00:00'
            return datetime.fromisoformat(dt_str)
        except Exception:
            return None

    cert_props = CertificateProperties(
        subject_name=props.get("subjectName"),
        issuer_name=props.get("issuerName"),
        not_valid_before=_parse_dt(props.get("notValidBefore")),
        not_valid_after=_parse_dt(props.get("notValidAfter")),
        signature_algorithm_ref=props.get("signatureAlgorithm"),
        subject_public_key_ref=props.get("subjectPublicKeyReference"),
        certificate_format="X.509",
        certificate_extension=".crt"
    )
    
    return CryptoProperties(
        asset_type=CryptoAssetType.CERTIFICATE,
        certificate_properties=cert_props
    )


def enrich_component_with_crypto(component: Component, asset: CanonicalAsset):
    """
    Enriches a CycloneDX Component with CryptoProperties if the asset is cryptographic.
    """
    if asset.asset_type == AssetType.ALGORITHM:
        component.crypto_properties = _map_algorithm(asset)
    elif asset.asset_type == AssetType.CERTIFICATE:
        component.crypto_properties = _map_certificate(asset)
    elif asset.asset_type == AssetType.KEY:
        # CycloneDX related_crypto_material_properties
        rel_props = RelatedCryptoMaterialProperties(
            type="private-key" if "private" in asset.name.lower() else "public-key",
            size=asset.properties.get("keySize")
        )
        component.crypto_properties = CryptoProperties(
            asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            related_crypto_material_properties=rel_props
        )
    elif asset.asset_type == AssetType.PROTOCOL:
        proto_props = ProtocolProperties(
            type=ProtocolPropertiesType.TLS if "tls" in asset.name.lower() else ProtocolPropertiesType.OTHER,
            version=asset.name.split()[-1] if " " in asset.name else asset.name
        )
        component.crypto_properties = CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=proto_props
        )
