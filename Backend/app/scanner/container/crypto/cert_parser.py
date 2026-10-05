"""
QuantumShield — Deep X.509 Certificate & Chain Analyzer

Safely inspects X.509 certificates and certificate bundles (.pem, .crt, .cer, .der).
Extracts:
  - Subject, Issuer, Serial Number, Validity Dates, Expiry Status
  - Public key algorithm, key size, curve name
  - Signature algorithm and signature OID
  - SHA-256 certificate fingerprint & Subject/Authority Key Identifiers
  - SANs (Subject Alternative Names), Key Usage, Extended Key Usage, CA Basic Constraints
Performs static certificate chain reconstruction and trust classification without remote calls.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PQCClassification,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Common OID to human-readable mappings
OID_MAP = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # PQC Draft OIDs (ML-DSA / ML-KEM)
    "2.16.840.1.101.3.4.3.17": "ml-dsa-44",
    "2.16.840.1.101.3.4.3.18": "ml-dsa-65",
    "2.16.840.1.101.3.4.3.19": "ml-dsa-87",
}


class CertificateParser:
    """Safe X.509 certificate extractor and chain analyzer."""

    @classmethod
    def parse_file(cls, filepath: str, target_id: str = "local") -> List[CryptoObservation]:
        """Parse all certificates found within a file (handles single or multi-cert PEMs/DER)."""
        observations: List[CryptoObservation] = []
        if not os.path.isfile(filepath):
            return observations

        try:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()
        except Exception as exc:
            logger.debug("Cannot read cert file %s: %s", filepath, exc)
            return observations

        if not raw_bytes:
            return observations

        # Try parsing as PEM bundle
        if b"-----BEGIN CERTIFICATE-----" in raw_bytes:
            observations.extend(cls.parse_pem_bundle(raw_bytes, filepath, target_id))
        else:
            # Try parsing as binary DER
            der_obs = cls.parse_der(raw_bytes, filepath, target_id)
            if der_obs:
                observations.append(der_obs)

        return observations

    @classmethod
    def parse_pem_bundle(cls, raw_bytes: bytes, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract one or more certificates from PEM text."""
        from cryptography import x509

        observations: List[CryptoObservation] = []
        # Split multiple PEM certificates
        pattern = re.compile(
            rb"-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----",
            re.DOTALL,
        )
        matches = pattern.findall(raw_bytes)

        for idx, pem_block in enumerate(matches):
            try:
                cert = x509.load_pem_x509_certificate(pem_block)
                obs = cls._build_cert_observation(cert, filepath, target_id, cert_index=idx)
                if obs:
                    observations.append(obs)
            except Exception as exc:
                logger.debug("Failed parsing PEM certificate #%d in %s: %s", idx, filepath, exc)

        return observations

    @classmethod
    def parse_der(cls, raw_bytes: bytes, filepath: str, target_id: str) -> Optional[CryptoObservation]:
        """Extract certificate from binary DER format."""
        from cryptography import x509

        try:
            cert = x509.load_der_x509_certificate(raw_bytes)
            return cls._build_cert_observation(cert, filepath, target_id, cert_index=0)
        except Exception:
            return None

    @classmethod
    def _build_cert_observation(
        cls, cert, filepath: str, target_id: str, cert_index: int = 0
    ) -> Optional[CryptoObservation]:
        """Extract metadata into normalized CryptoObservation."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
        from cryptography.x509.oid import ExtensionOID, NameOID

        try:
            # Subject and Issuer
            subject_str = cert.subject.rfc4514_string()
            issuer_str = cert.issuer.rfc4514_string()

            subject_cn = cls._extract_attribute(cert.subject, NameOID.COMMON_NAME) or subject_str[:64]
            issuer_cn = cls._extract_attribute(cert.issuer, NameOID.COMMON_NAME) or issuer_str[:64]

            # Validity Dates
            now = datetime.now(timezone.utc)
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_until_expiry = (not_after - now).days
            is_expired = days_until_expiry < 0

            # Public Key
            pub_key = cert.public_key()
            algo = "unknown"
            key_size = None
            curve_name = None
            pub_fingerprint = None

            if isinstance(pub_key, rsa.RSAPublicKey):
                algo = "RSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                algo = "EC"
                key_size = pub_key.key_size
                curve_name = pub_key.curve.name
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                algo = "Ed25519"
                key_size = 256
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                algo = "Ed448"
                key_size = 448
            elif isinstance(pub_key, dsa.DSAPublicKey):
                algo = "DSA"
                key_size = pub_key.key_size

            # Compute Public Key SHA-256 fingerprint for correlation
            try:
                from cryptography.hazmat.primitives import serialization
                pub_der = pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                pub_fingerprint = hashlib.sha256(pub_der).hexdigest()
            except Exception:
                pass

            # Signature Algorithm
            sig_oid = cert.signature_algorithm_oid.dotted_string
            sig_name = OID_MAP.get(sig_oid) or getattr(cert.signature_algorithm_oid, "_name", sig_oid)

            # Certificate Fingerprint
            cert_fp = cert.fingerprint(hashes.SHA256()).hex(":")

            # SANs
            sans: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [str(x.value) for x in san_ext.value]
            except Exception:
                pass

            # Basic Constraints (CA)
            is_ca = False
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                is_ca = bool(bc.ca)
            except Exception:
                pass

            # Subject Key Identifier (SKI) & Authority Key Identifier (AKI)
            ski = None
            try:
                ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
                ski = ski_ext.digest.hex()
            except Exception:
                pass

            aki = None
            try:
                aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
                if aki_ext.key_identifier:
                    aki = aki_ext.key_identifier.hex()
            except Exception:
                pass

            # Self-signed check
            is_self_signed = (cert.subject == cert.issuer)

            # PQC classification
            pqc_class = PQCClassification.CLASSICAL.value
            if any(p in sig_name.lower() or p in algo.lower() for p in ("ml-dsa", "dilithium", "sphincs", "falcon")):
                pqc_class = PQCClassification.PQC_USAGE_OBSERVED.value

            return CryptoObservation(
                target_id=target_id,
                target_type="certificate",
                file_path=filepath,
                artifact_type=ArtifactType.CERTIFICATE.value,
                algorithm=algo,
                key_size=key_size,
                curve=curve_name,
                signature_algorithm=sig_name,
                fingerprint=cert_fp,
                pqc_classification=pqc_class,
                confidence=ConfidenceLevel.HIGH,
                parser="x509_crypto_parser",
                evidence={
                    "cert_index": cert_index,
                    "subject": subject_str,
                    "subject_cn": subject_cn,
                    "issuer": issuer_str,
                    "issuer_cn": issuer_cn,
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": not_before.isoformat(),
                    "not_valid_after": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "expired": is_expired,
                    "sans": sans[:20],
                    "is_ca": is_ca,
                    "is_self_signed": is_self_signed,
                    "ski": ski,
                    "aki": aki,
                    "public_key_fingerprint": pub_fingerprint,
                },
            )

        except Exception as exc:
            logger.debug("Failed building cert observation for %s: %s", filepath, exc)
            return None

    @staticmethod
    def _extract_attribute(name, oid) -> Optional[str]:
        """Extract first value matching OID from an X.509 Name."""
        try:
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                val = attrs[0].value
                return val.decode("utf-8") if isinstance(val, bytes) else str(val)
        except Exception:
            pass
        return None

    @classmethod
    def reconstruct_chains(cls, cert_observations: List[CryptoObservation]) -> List[dict]:
        """
        Statically correlate certificates into potential chains using Subject/Issuer and SKI/AKI.
        Classifies each certificate into leaf, intermediate, root, or unknown.
        """
        # Map by Subject and SKI
        by_subject = {}
        by_ski = {}
        for obs in cert_observations:
            subj = obs.evidence.get("subject")
            ski = obs.evidence.get("ski")
            if subj:
                by_subject[subj] = obs
            if ski:
                by_ski[ski] = obs

        chains: List[dict] = []
        for obs in cert_observations:
            ev = obs.evidence
            is_self_signed = ev.get("is_self_signed", False)
            is_ca = ev.get("is_ca", False)

            if is_self_signed and is_ca:
                role = "root"
            elif is_ca:
                role = "intermediate"
            else:
                role = "leaf"

            # Attempt to find parent
            issuer = ev.get("issuer")
            aki = ev.get("aki")
            parent_fp = None

            if aki and aki in by_ski and by_ski[aki].fingerprint != obs.fingerprint:
                parent_fp = by_ski[aki].fingerprint
            elif issuer and issuer in by_subject and by_subject[issuer].fingerprint != obs.fingerprint:
                parent_fp = by_subject[issuer].fingerprint

            ev["chain_role"] = role
            ev["parent_fingerprint"] = parent_fp

            chains.append({
                "fingerprint": obs.fingerprint,
                "role": role,
                "parent_fingerprint": parent_fp,
                "subject_cn": ev.get("subject_cn"),
                "issuer_cn": ev.get("issuer_cn"),
            })

        return chains
