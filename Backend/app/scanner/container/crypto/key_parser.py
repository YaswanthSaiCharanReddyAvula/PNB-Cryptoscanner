"""
QuantumShield — Cryptographic Key Analyzer (Private & Public Keys)

Safely inspects private and public keys in PEM, DER, and OpenSSH formats.
Extracts:
  - Algorithm (RSA, EC, Ed25519, Ed448, DSA)
  - Key size in bits
  - Curve name for elliptic curves
  - Safe SHA-256 fingerprint of the associated public key
  - Encryption status (encrypted vs plaintext)
CRITICAL SECURITY INVARIANT:
  NEVER stores, logs, or transmits raw private key bytes!
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, List, Optional

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PQCClassification,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class KeyParser:
    """Safe static parser for asymmetric keys."""

    @classmethod
    def parse_file(cls, filepath: str, target_id: str = "local") -> List[CryptoObservation]:
        """Inspect file for private or public key artifacts."""
        observations: List[CryptoObservation] = []
        if not os.path.isfile(filepath):
            return observations

        try:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()
        except Exception as exc:
            logger.debug("Cannot read key file %s: %s", filepath, exc)
            return observations

        if not raw_bytes:
            return observations

        # 1. Check for PEM Private Keys
        if b"PRIVATE KEY-----" in raw_bytes:
            priv_obs = cls.parse_pem_private_keys(raw_bytes, filepath, target_id)
            observations.extend(priv_obs)

        # 2. Check for PEM Public Keys
        if b"PUBLIC KEY-----" in raw_bytes:
            pub_obs = cls.parse_pem_public_keys(raw_bytes, filepath, target_id)
            observations.extend(pub_obs)

        # 3. Check for OpenSSH Public Keys (single-line format)
        if any(raw_bytes.startswith(p) for p in (b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-")):
            ssh_obs = cls.parse_openssh_public_key(raw_bytes, filepath, target_id)
            if ssh_obs:
                observations.append(ssh_obs)

        return observations

    @classmethod
    def parse_pem_private_keys(cls, raw_bytes: bytes, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Detect and safely parse private keys without saving secret material."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

        observations: List[CryptoObservation] = []
        pattern = re.compile(
            rb"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[^-]+-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
            re.DOTALL,
        )
        matches = pattern.findall(raw_bytes)

        for idx, pem_block in enumerate(matches):
            header_line = pem_block.splitlines()[0].decode("ascii", "ignore")
            is_encrypted_header = "ENCRYPTED" in header_line
            format_name = "PKCS#8" if "BEGIN PRIVATE KEY" in header_line else "PKCS#1" if "RSA" in header_line else "SEC1" if "EC" in header_line else "OpenSSH"

            try:
                # Attempt to load without password
                key = serialization.load_pem_private_key(pem_block, password=None)
                # Key is unencrypted
                algo = "unknown"
                key_size = None
                curve_name = None

                pub = key.public_key()
                if isinstance(key, rsa.RSAPrivateKey):
                    algo = "RSA"
                    key_size = key.key_size
                elif isinstance(key, ec.EllipticCurvePrivateKey):
                    algo = "EC"
                    key_size = key.key_size
                    curve_name = key.curve.name
                elif isinstance(key, ed25519.Ed25519PrivateKey):
                    algo = "Ed25519"
                    key_size = 256
                elif isinstance(key, ed448.Ed448PrivateKey):
                    algo = "Ed448"
                    key_size = 448
                elif isinstance(key, dsa.DSAPrivateKey):
                    algo = "DSA"
                    key_size = key.key_size

                # Compute public key fingerprint for correlation with certificates
                pub_der = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                pub_fp = hashlib.sha256(pub_der).hexdigest()

                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="private_key",
                        file_path=filepath,
                        artifact_type=ArtifactType.PRIVATE_KEY.value,
                        algorithm=algo,
                        key_size=key_size,
                        curve=curve_name,
                        fingerprint=pub_fp,
                        pqc_classification=PQCClassification.CLASSICAL.value,
                        confidence=ConfidenceLevel.HIGH,
                        parser="pem_private_key_parser",
                        evidence={
                            "key_index": idx,
                            "format": format_name,
                            "is_encrypted": False,
                            "public_key_fingerprint": pub_fp,
                            "header": header_line,
                        },
                    )
                )

            except (TypeError, ValueError) as exc:
                # Key is password-protected or unsupported format
                is_encrypted = is_encrypted_header or "password was not given" in str(exc).lower() or "encrypted" in str(exc).lower()

                # Infer algorithm from header if possible
                algo = "RSA" if "RSA" in header_line else "EC" if "EC" in header_line else "DSA" if "DSA" in header_line else "AsymmetricKey"
                # Compute safe SHA-256 fingerprint of the sanitized header
                safe_fp = hashlib.sha256(pem_block[:128]).hexdigest()

                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="private_key",
                        file_path=filepath,
                        artifact_type=ArtifactType.PRIVATE_KEY.value,
                        algorithm=algo,
                        fingerprint=safe_fp,
                        pqc_classification=PQCClassification.CLASSICAL.value,
                        confidence=ConfidenceLevel.MEDIUM if is_encrypted else ConfidenceLevel.LOW,
                        parser="pem_encrypted_key_detector",
                        evidence={
                            "key_index": idx,
                            "format": format_name,
                            "is_encrypted": is_encrypted,
                            "status": "ENCRYPTED_UNINSPECTED" if is_encrypted else "UNPARSEABLE_PRIVATE_KEY",
                            "header": header_line,
                            "safe_hash": safe_fp,
                        },
                    )
                )
            except Exception as exc:
                logger.debug("Failed parsing private key #%d in %s: %s", idx, filepath, exc)

        return observations

    @classmethod
    def parse_pem_public_keys(cls, raw_bytes: bytes, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Detect and parse public keys."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

        observations: List[CryptoObservation] = []
        pattern = re.compile(
            rb"-----BEGIN (?:[A-Z0-9_-]+ )?PUBLIC KEY-----[^-]+-----END (?:[A-Z0-9_-]+ )?PUBLIC KEY-----",
            re.DOTALL,
        )
        matches = pattern.findall(raw_bytes)

        for idx, pem_block in enumerate(matches):
            try:
                pub = serialization.load_pem_public_key(pem_block)
                algo = "unknown"
                key_size = None
                curve_name = None

                if isinstance(pub, rsa.RSAPublicKey):
                    algo = "RSA"
                    key_size = pub.key_size
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    algo = "EC"
                    key_size = pub.key_size
                    curve_name = pub.curve.name
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    algo = "Ed25519"
                    key_size = 256
                elif isinstance(pub, ed448.Ed448PublicKey):
                    algo = "Ed448"
                    key_size = 448
                elif isinstance(pub, dsa.DSAPublicKey):
                    algo = "DSA"
                    key_size = pub.key_size

                pub_der = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                pub_fp = hashlib.sha256(pub_der).hexdigest()

                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="public_key",
                        file_path=filepath,
                        artifact_type=ArtifactType.PUBLIC_KEY.value,
                        algorithm=algo,
                        key_size=key_size,
                        curve=curve_name,
                        fingerprint=pub_fp,
                        pqc_classification=PQCClassification.CLASSICAL.value,
                        confidence=ConfidenceLevel.HIGH,
                        parser="pem_public_key_parser",
                        evidence={
                            "key_index": idx,
                            "public_key_fingerprint": pub_fp,
                        },
                    )
                )
            except Exception as exc:
                logger.debug("Failed parsing public key #%d in %s: %s", idx, filepath, exc)

        return observations

    @classmethod
    def parse_openssh_public_key(cls, raw_bytes: bytes, filepath: str, target_id: str) -> Optional[CryptoObservation]:
        """Parse OpenSSH format public keys."""
        from cryptography.hazmat.primitives import serialization

        try:
            pub = serialization.load_ssh_public_key(raw_bytes.strip())
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

            algo = "unknown"
            key_size = None
            curve_name = None

            if isinstance(pub, rsa.RSAPublicKey):
                algo = "RSA"
                key_size = pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                algo = "EC"
                key_size = pub.key_size
                curve_name = pub.curve.name
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                algo = "Ed25519"
                key_size = 256

            pub_der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            pub_fp = hashlib.sha256(pub_der).hexdigest()

            return CryptoObservation(
                target_id=target_id,
                target_type="public_key",
                file_path=filepath,
                artifact_type=ArtifactType.PUBLIC_KEY.value,
                algorithm=algo,
                key_size=key_size,
                curve=curve_name,
                fingerprint=pub_fp,
                confidence=ConfidenceLevel.HIGH,
                parser="openssh_public_key_parser",
                evidence={"public_key_fingerprint": pub_fp, "format": "OpenSSH"},
            )
        except Exception:
            return None

    @classmethod
    def correlate_keys_and_certs(
        cls, keys: List[CryptoObservation], certs: List[CryptoObservation]
    ) -> List[dict]:
        """
        Correlate private keys with certificates via public key SHA-256 fingerprint equality.
        Never infers correlation merely from identical filenames!
        """
        correlations = []
        for k in keys:
            k_pub_fp = k.evidence.get("public_key_fingerprint")
            if not k_pub_fp:
                continue

            for c in certs:
                c_pub_fp = c.evidence.get("public_key_fingerprint")
                if c_pub_fp and c_pub_fp == k_pub_fp:
                    correlations.append({
                        "key_path": k.file_path,
                        "key_algorithm": k.algorithm,
                        "key_size": k.key_size,
                        "cert_path": c.file_path,
                        "cert_subject_cn": c.evidence.get("subject_cn"),
                        "public_key_fingerprint": k_pub_fp,
                        "confidence": "HIGH",
                        "correlation_type": "public_key_cryptographic_match",
                    })

        return correlations
