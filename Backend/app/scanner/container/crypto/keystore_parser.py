"""
QuantumShield — Safe Keystore & Trust Store Analyzer

Safely inspects PKCS#12, JKS, and Trust Store bundles without brute-forcing passwords.
If a keystore is encrypted and requires a password:
  status = "ENCRYPTED_UNINSPECTED"
Extracts certificate chains, root CAs, and algorithms where accessible.
"""

from __future__ import annotations

import hashlib
import os
from typing import List, Optional

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PQCClassification,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_JKS_MAGIC = b"\xfe\xed\xfe\xed"


class KeystoreParser:
    """Safe keystore and trust store inspector."""

    @classmethod
    def parse_file(cls, filepath: str, target_id: str = "local") -> List[CryptoObservation]:
        """Inspect file for keystores or trust stores."""
        observations: List[CryptoObservation] = []
        if not os.path.isfile(filepath):
            return observations

        basename = os.path.basename(filepath).lower()
        ext = os.path.splitext(basename)[1].lower()

        try:
            with open(filepath, "rb") as f:
                header = f.read(4096)
        except Exception:
            return observations

        # 1. JKS Detection
        if header.startswith(_JKS_MAGIC) or ext == ".jks":
            jks_obs = cls._handle_jks(filepath, header, target_id)
            if jks_obs:
                observations.append(jks_obs)
            return observations

        # 2. PKCS#12 (.p12, .pfx)
        if ext in (".p12", ".pfx"):
            p12_obs = cls._handle_pkcs12(filepath, target_id)
            observations.extend(p12_obs)
            return observations

        # 3. Known Trust Store Files
        if basename in ("ca-certificates.crt", "ca-bundle.crt", "cacerts"):
            ts_obs = cls._handle_trust_store(filepath, target_id)
            if ts_obs:
                observations.append(ts_obs)

        return observations

    @classmethod
    def _handle_jks(cls, filepath: str, header: bytes, target_id: str) -> CryptoObservation:
        """Handle Java KeyStore statically without password guessing."""
        safe_hash = hashlib.sha256(header[:256]).hexdigest()
        return CryptoObservation(
            target_id=target_id,
            target_type="keystore",
            file_path=filepath,
            artifact_type=ArtifactType.KEYSTORE.value,
            algorithm="JKS",
            fingerprint=safe_hash,
            pqc_classification=PQCClassification.CLASSICAL.value,
            confidence=ConfidenceLevel.HIGH,
            parser="jks_detector",
            evidence={
                "format": "JKS",
                "status": "ENCRYPTED_UNINSPECTED",
                "note": "Binary JKS format requires password — brute-forcing prohibited by security policy",
                "safe_hash": safe_hash,
            },
        )

    @classmethod
    def _handle_pkcs12(cls, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Attempt safe passwordless extraction of PKCS#12."""
        from cryptography.hazmat.primitives.serialization import pkcs12

        observations: List[CryptoObservation] = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()

            safe_hash = hashlib.sha256(data[:256]).hexdigest()

            # Attempt load with empty password
            try:
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password=None)
            except (TypeError, ValueError):
                # Try empty byte password
                try:
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password=b"")
                except Exception:
                    # Password protected
                    observations.append(
                        CryptoObservation(
                            target_id=target_id,
                            target_type="keystore",
                            file_path=filepath,
                            artifact_type=ArtifactType.KEYSTORE.value,
                            algorithm="PKCS12",
                            fingerprint=safe_hash,
                            pqc_classification=PQCClassification.CLASSICAL.value,
                            confidence=ConfidenceLevel.HIGH,
                            parser="pkcs12_parser",
                            evidence={
                                "format": "PKCS#12",
                                "status": "ENCRYPTED_UNINSPECTED",
                                "note": "PKCS#12 container is password-protected — password guessing prohibited",
                                "safe_hash": safe_hash,
                            },
                        )
                    )
                    return observations

            # If opened without password:
            cert_count = (1 if cert else 0) + len(additional_certs or [])
            observations.append(
                CryptoObservation(
                    target_id=target_id,
                    target_type="keystore",
                    file_path=filepath,
                    artifact_type=ArtifactType.KEYSTORE.value,
                    algorithm="PKCS12",
                    fingerprint=safe_hash,
                    confidence=ConfidenceLevel.HIGH,
                    parser="pkcs12_parser",
                    evidence={
                        "format": "PKCS#12",
                        "status": "INSPECTED_EMPTY_PASSWORD",
                        "has_private_key": private_key is not None,
                        "certificate_count": cert_count,
                        "safe_hash": safe_hash,
                    },
                )
            )

        except Exception as exc:
            logger.debug("Error processing PKCS12 file %s: %s", filepath, exc)

        return observations

    @classmethod
    def _handle_trust_store(cls, filepath: str, target_id: str) -> Optional[CryptoObservation]:
        """Count and summarize certificates in a system CA trust bundle."""
        from app.scanner.container.crypto.cert_parser import CertificateParser

        certs = CertificateParser.parse_file(filepath, target_id)
        if not certs:
            return None

        safe_hash = hashlib.sha256(filepath.encode()).hexdigest()
        ca_issuers = list({c.evidence.get("issuer_cn") for c in certs if c.evidence.get("issuer_cn")})

        return CryptoObservation(
            target_id=target_id,
            target_type="trust_store",
            file_path=filepath,
            artifact_type=ArtifactType.TRUST_STORE.value,
            algorithm="X.509 Trust Store",
            fingerprint=safe_hash,
            confidence=ConfidenceLevel.HIGH,
            parser="trust_store_parser",
            evidence={
                "store_type": "PEM CA Bundle",
                "certificate_count": len(certs),
                "issuers_sample": ca_issuers[:15],
                "safe_hash": safe_hash,
            },
        )
