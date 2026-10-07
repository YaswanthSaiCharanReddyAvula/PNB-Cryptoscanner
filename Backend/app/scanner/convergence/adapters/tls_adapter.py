"""
QuantumShield — Convergence TLS Adapter

Transforms TLS profiles and associated cryptographic data into canonical models.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
    Identifier,
    Location,
    Relationship,
)
from app.scanner.convergence.enums import AssetType, ObservationStatus
from app.scanner.convergence.normalizers import (
    normalize_hostname,
    normalize_port,
)
from app.scanner.models import TLSProfile
from app.scanner.pipeline import ScanContext


class TLSAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "tls_engine"

    @property
    def engine_stage(self) -> str:
        return "network/tls"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        for profile in ctx.tls_profiles:
            # 1. Represent the service
            host = normalize_hostname(profile.host)
            port_info = normalize_port(profile.port)
            service_id = f"svc:{host}:{port_info['port']}:{port_info['transport']}"
            
            service_asset = CanonicalAsset(
                scan_id=ctx.scan_id,
                asset_type=AssetType.SERVICE,
                name=f"TLS Service {host}:{port_info['port']}",
                identifiers=[
                    Identifier(type="hostname", value=host),
                    Identifier(type="port", value=str(port_info["port"]))
                ],
                locations=[
                    Location(type="endpoint", value=f"{host}:{port_info['port']}")
                ],
                observed_at=now,
                sources=[self.engine_name]
            )
            assets.append(service_asset)

            # 2. Represent the certificates
            for cert in profile.cert_chain:
                if not cert.fingerprint_sha256:
                    continue
                    
                cert_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.CERTIFICATE,
                    name=cert.subject or "Unknown Certificate",
                    identifiers=[
                        Identifier(type="fingerprint", value=cert.fingerprint_sha256)
                    ],
                    properties={
                        "subjectName": cert.subject,
                        "issuerName": cert.issuer,
                        "notValidBefore": cert.valid_from,
                        "notValidAfter": cert.valid_to,
                        "signatureAlgorithm": cert.sig_algorithm,
                        "signatureAlgorithmOid": getattr(cert, 'sig_algorithm_oid', None),
                        "subjectPublicKeyReference": getattr(cert, 'subject_public_key_ref', None),
                        "keyType": cert.key_type,
                        "keySize": cert.key_size
                    },
                    observed_at=now,
                    sources=[self.engine_name],
                    relationships=[
                        Relationship(type="served_by", target_id=service_asset.asset_id)
                    ]
                )
                assets.append(cert_asset)
                
                # Add evidence for certificate observation
                cert_evidence = CanonicalEvidence(
                    scan_id=ctx.scan_id,
                    source_engine=self.engine_name,
                    source_stage=self.engine_stage,
                    observation_type="certificate",
                    target=host,
                    observed_at=now,
                    value_hash=cert.fingerprint_sha256
                )
                evidence.append(cert_evidence)
                cert_asset.evidence_refs.append(cert_evidence.evidence_id)

            # 3. Represent TLS Protocols
            for proto, supported in profile.tls_versions_supported.items():
                if supported:
                    proto_asset = CanonicalAsset(
                        scan_id=ctx.scan_id,
                        asset_type=AssetType.PROTOCOL,
                        name=proto,
                        observed_at=now,
                        sources=[self.engine_name],
                        relationships=[
                            Relationship(type="supported_by", target_id=service_asset.asset_id)
                        ]
                    )
                    assets.append(proto_asset)

            # 4. Represent Cryptographic Algorithms (Ciphers)
            for cipher in profile.accepted_ciphers:
                algo_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.ALGORITHM,
                    name=cipher.name,
                    properties={
                        "primitive": getattr(cipher, 'primitive', None),
                        "mode": getattr(cipher, 'mode', None),
                        "crypto_functions": getattr(cipher, 'crypto_functions', None),
                        "classical_security_level": getattr(cipher, 'classical_security_level', None),
                        "oid": getattr(cipher, 'oid', None)
                    },
                    observed_at=now,
                    sources=[self.engine_name],
                    relationships=[
                        Relationship(type="accepted_by", target_id=service_asset.asset_id)
                    ]
                )
                assets.append(algo_asset)
                
                algo_evidence = CanonicalEvidence(
                    scan_id=ctx.scan_id,
                    source_engine=self.engine_name,
                    source_stage=self.engine_stage,
                    observation_type="cipher_suite",
                    target=host,
                    observed_at=now,
                    value=cipher.name
                )
                evidence.append(algo_evidence)
                algo_asset.evidence_refs.append(algo_evidence.evidence_id)

        return assets, findings, evidence
