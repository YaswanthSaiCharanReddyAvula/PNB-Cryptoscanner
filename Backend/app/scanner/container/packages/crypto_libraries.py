"""
QuantumShield — Cryptographic Library & Primitive Matcher

Cross-references discovered packages and shared libraries against known
cryptographic implementations, extracting supported primitives and PQC capabilities.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PackageObservation,
    PQCClassification,
)

# Curated registry of known cryptographic libraries across OS and language ecosystems
_KNOWN_CRYPTO_LIBRARIES: Dict[str, dict] = {
    # System / C libraries
    "libssl": {
        "desc": "OpenSSL / LibreSSL SSL library",
        "primitives": ["TLS", "AES", "RSA", "ECDSA", "SHA-2"],
        "pqc": [],
    },
    "libcrypto": {
        "desc": "OpenSSL / LibreSSL Core Crypto library",
        "primitives": ["AES", "RSA", "ECDSA", "ECDH", "SHA-2", "ChaCha20", "Poly1305"],
        "pqc": [],
    },
    "openssl": {
        "desc": "OpenSSL toolkit",
        "primitives": ["TLS", "AES", "RSA", "ECDSA", "SHA-2"],
        "pqc": [],
    },
    "liboqs": {
        "desc": "Open Quantum Safe C library",
        "primitives": ["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS+"],
        "pqc": ["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "SPHINCS+"],
    },
    "libsodium": {
        "desc": "NaCl / libsodium cryptography library",
        "primitives": ["Curve25519", "Ed25519", "XSalsa20", "Poly1305", "BLAKE2"],
        "pqc": [],
    },
    "libgcrypt": {
        "desc": "GNU General Crypto Library",
        "primitives": ["AES", "RSA", "ECC", "SHA-2"],
        "pqc": [],
    },
    "mbedtls": {
        "desc": "ARM mbed TLS",
        "primitives": ["TLS", "AES", "RSA", "ECC"],
        "pqc": [],
    },
    "wolfssl": {
        "desc": "wolfSSL embedded SSL/TLS",
        "primitives": ["TLS", "AES", "RSA", "ECC", "Kyber", "Dilithium"],
        "pqc": ["Kyber", "Dilithium"],
    },

    # Python
    "cryptography": {
        "desc": "Python Cryptographic Authority recipe library",
        "primitives": ["AES", "RSA", "ECDSA", "ECDH", "ChaCha20", "SHA-2"],
        "pqc": [],
    },
    "pycryptodome": {
        "desc": "Python crypto toolkit",
        "primitives": ["AES", "RSA", "ECC", "SHA-2"],
        "pqc": [],
    },
    "pycryptodomex": {
        "desc": "Python crypto toolkit (bare)",
        "primitives": ["AES", "RSA", "ECC", "SHA-2"],
        "pqc": [],
    },
    "pynacl": {
        "desc": "Python binding to libsodium",
        "primitives": ["Ed25519", "Curve25519", "ChaCha20-Poly1305"],
        "pqc": [],
    },
    "pyopenssl": {
        "desc": "Python OpenSSL wrapper",
        "primitives": ["TLS", "X509"],
        "pqc": [],
    },
    "bcrypt": {
        "desc": "Password hashing library",
        "primitives": ["bcrypt"],
        "pqc": [],
    },

    # Node.js
    "crypto-js": {
        "desc": "JavaScript crypto standard library",
        "primitives": ["AES", "DES", "SHA-2", "HMAC"],
        "pqc": [],
    },
    "jsonwebtoken": {
        "desc": "Node JWT implementation",
        "primitives": ["JWT", "HMAC", "RSA"],
        "pqc": [],
    },
    "node-forge": {
        "desc": "Pure JS TLS and PKI",
        "primitives": ["TLS", "RSA", "AES", "X509"],
        "pqc": [],
    },
    "tweetnacl": {
        "desc": "Pure JS NaCl implementation",
        "primitives": ["Curve25519", "Ed25519", "XSalsa20"],
        "pqc": [],
    },

    # Java
    "org.bouncycastle:bcprov-jdk15on": {
        "desc": "BouncyCastle Crypto Provider",
        "primitives": ["AES", "RSA", "ECC", "SHA-2"],
        "pqc": ["Dilithium", "Kyber", "SPHINCS+"],
    },
    "org.bouncycastle:bcprov-jdk18on": {
        "desc": "BouncyCastle Crypto Provider",
        "primitives": ["AES", "RSA", "ECC", "SHA-2"],
        "pqc": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    },
    "org.bouncycastle:bcpqc-addon-fips": {
        "desc": "BouncyCastle Post-Quantum Cryptography",
        "primitives": ["ML-KEM", "ML-DSA", "SLH-DSA"],
        "pqc": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    },
    "com.google.crypto.tink:tink": {
        "desc": "Google Tink cryptography library",
        "primitives": ["AES", "RSA", "ECDSA", "Ed25519", "ChaCha20-Poly1305"],
        "pqc": [],
    },

    # Go
    "golang.org/x/crypto": {
        "desc": "Extended Go cryptography packages",
        "primitives": ["Argon2", "SSH", "NaCl", "Ed25519", "ChaCha20-Poly1305"],
        "pqc": [],
    },
    "github.com/cloudflare/circl": {
        "desc": "Cloudflare CIRCL PQC & Advanced Crypto",
        "primitives": ["ECC", "X25519", "Kyber", "Dilithium"],
        "pqc": ["Kyber", "Dilithium"],
    },
}


class CryptoLibraryMatcher:
    """Matches packages to known crypto profiles and produces normalized observations."""

    @classmethod
    def match_package(cls, pkg: PackageObservation, target_id: str) -> Optional[CryptoObservation]:
        """Check if package is a known crypto library and enrich it."""
        clean_name = pkg.name.lower().strip()

        # Check direct or prefix matches
        matched_entry = None
        for key, info in _KNOWN_CRYPTO_LIBRARIES.items():
            if clean_name == key.lower() or clean_name.startswith(key.lower() + "-") or clean_name.startswith(key.lower() + "_"):
                matched_entry = info
                break

        if not matched_entry:
            # Check for generic crypto tokens in name (e.g. libssl3, openssl-dev)
            if any(t in clean_name for t in ("libcrypto", "libssl", "openssl", "bouncycastle", "libsodium")):
                matched_entry = {
                    "desc": f"Cryptographic component ({clean_name})",
                    "primitives": ["Cryptographic Library"],
                    "pqc": [],
                }

        if matched_entry:
            pkg.is_crypto_relevant = True
            pkg.crypto_primitives = matched_entry.get("primitives", [])
            pkg.pqc_support = matched_entry.get("pqc", [])

            pqc_class = PQCClassification.CLASSICAL.value
            if pkg.pqc_support:
                pqc_class = PQCClassification.PQC_CAPABLE_LIBRARY.value

            return CryptoObservation(
                target_id=target_id,
                target_type="crypto_library",
                file_path=pkg.source_file,
                artifact_type=ArtifactType.CRYPTO_LIBRARY.value,
                algorithm=f"Library: {pkg.name}",
                pqc_classification=pqc_class,
                confidence=ConfidenceLevel.HIGH,
                parser="crypto_library_registry",
                evidence={
                    "package_name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "description": matched_entry.get("desc"),
                    "primitives": pkg.crypto_primitives,
                    "pqc_support": pkg.pqc_support,
                },
            )

        return None
