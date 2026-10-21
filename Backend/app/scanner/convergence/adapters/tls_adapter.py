"""
QuantumShield — Convergence TLS Adapter

Transforms TLS profiles and associated cryptographic data into canonical models.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
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
from app.utils.logger import get_logger

logger = get_logger(__name__)


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

        for profile in getattr(ctx, "tls_profiles", []):
            if not isinstance(profile, (dict, TLSProfile)) and not hasattr(profile, "host"):
                msg = f"Skipping malformed TLS profile record: invalid type {type(profile).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            raw_host = extract_field(profile, "host")
            raw_port = extract_field(profile, "port")
            if not raw_host or raw_port is None:
                msg = f"Skipping TLS profile missing required host or port: host={raw_host!r}, port={raw_port!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            try:
                port_num = int(raw_port)
            except (ValueError, TypeError):
                msg = f"Skipping TLS profile with invalid port: {raw_port!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            host = normalize_hostname(str(raw_host))
            if not host or port_num <= 0:
                msg = f"Skipping TLS profile with empty host or non-positive port: {host!r}:{port_num}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            # 1. Represent the service
            port_info = normalize_port(port_num)
            
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
            cert_chain = extract_field(profile, "cert_chain", []) or []
            if not cert_chain:
                leaf_cert = extract_field(profile, "leaf_cert")
                if leaf_cert:
                    cert_chain = [leaf_cert]

            for cert in cert_chain:
                fp = extract_field(cert, "fingerprint_sha256")
                if not fp:
                    msg = f"Skipping certificate missing required fingerprint_sha256 on {host}:{port_num}"
                    logger.warning(msg)
                    self.record_error(msg)
                    continue
                    
                subject = extract_field(cert, "subject") or "Unknown Certificate"
                cert_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.CERTIFICATE,
                    name=subject,
                    identifiers=[
                        Identifier(type="fingerprint", value=str(fp))
                    ],
                    properties={
                        "subjectName": extract_field(cert, "subject"),
                        "issuerName": extract_field(cert, "issuer"),
                        "notValidBefore": extract_field(cert, "valid_from"),
                        "notValidAfter": extract_field(cert, "valid_to"),
                        "signatureAlgorithm": extract_field(cert, "sig_algorithm"),
                        "signatureAlgorithmOid": extract_field(cert, "sig_algorithm_oid"),
                        "subjectPublicKeyReference": extract_field(cert, "subject_public_key_ref"),
                        "keyType": extract_field(cert, "key_type"),
                        "keySize": extract_field(cert, "key_size")
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
                    value_hash=str(fp)
                )
                evidence.append(cert_evidence)
                cert_asset.evidence_refs.append(cert_evidence.evidence_id)

            # 3. Represent TLS Protocols
            tls_versions = extract_field(profile, "tls_versions_supported", {}) or {}
            if isinstance(tls_versions, dict):
                for proto, supported in tls_versions.items():
                    if supported and isinstance(proto, str) and proto.strip():
                        proto_asset = CanonicalAsset(
                            scan_id=ctx.scan_id,
                            asset_type=AssetType.PROTOCOL,
                            name=proto.strip(),
                            observed_at=now,
                            sources=[self.engine_name],
                            relationships=[
                                Relationship(type="supported_by", target_id=service_asset.asset_id)
                            ]
                        )
                        assets.append(proto_asset)

            # 4. Represent Cryptographic Algorithms (Ciphers)
            accepted_ciphers = extract_field(profile, "accepted_ciphers", []) or []
            for cipher in accepted_ciphers:
                cipher_name = extract_field(cipher, "name")
                if not cipher_name or not isinstance(cipher_name, str):
                    msg = f"Skipping cipher missing valid name on {host}:{port_num}: {cipher!r}"
                    logger.warning(msg)
                    self.record_error(msg)
                    continue

                algo_asset = CanonicalAsset(
                    scan_id=ctx.scan_id,
                    asset_type=AssetType.ALGORITHM,
                    name=cipher_name.strip(),
                    properties={
                        "primitive": extract_field(cipher, "primitive"),
                        "mode": extract_field(cipher, "mode"),
                        "crypto_functions": extract_field(cipher, "crypto_functions"),
                        "classical_security_level": extract_field(cipher, "classical_security_level"),
                        "oid": extract_field(cipher, "oid")
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
                    value=cipher_name.strip()
                )
                evidence.append(algo_evidence)
                algo_asset.evidence_refs.append(algo_evidence.evidence_id)

        return assets, findings, evidence

