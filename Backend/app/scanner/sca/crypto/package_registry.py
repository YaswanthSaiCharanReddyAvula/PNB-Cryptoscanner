"""
QuantumShield — Crypto Package Intelligence

Maintains a controlled registry of known cryptographic libraries,
their primitives, and PQC capabilities.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from app.scanner.sca.models.package import Ecosystem, PackageIdentity


class CryptoPackageMetadata(BaseModel):
    package_name: str
    ecosystem: Ecosystem
    crypto_relevance: str
    primitives: List[str] = Field(default_factory=list)
    pqc_support: List[str] = Field(default_factory=list)


_CRYPTO_REGISTRY: List[CryptoPackageMetadata] = [
    # Python
    CryptoPackageMetadata(
        package_name="cryptography",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="General-purpose crypto (TLS, X.509, AES, RSA)",
        primitives=["AES", "RSA", "ECDSA", "ECDH", "SHA-2", "ChaCha20", "Poly1305"]
    ),
    CryptoPackageMetadata(
        package_name="pycryptodome",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="Symmetric + asymmetric encryption",
        primitives=["AES", "RSA", "ECC", "SHA-2"]
    ),
    CryptoPackageMetadata(
        package_name="pycryptodomex",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="Symmetric + asymmetric encryption",
        primitives=["AES", "RSA", "ECC", "SHA-2"]
    ),
    CryptoPackageMetadata(
        package_name="pyopenssl",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="OpenSSL TLS wrapper",
        primitives=["TLS", "X509"]
    ),
    CryptoPackageMetadata(
        package_name="bcrypt",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="Password hashing",
        primitives=["bcrypt"]
    ),
    CryptoPackageMetadata(
        package_name="argon2-cffi",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="Password hashing",
        primitives=["argon2"]
    ),
    CryptoPackageMetadata(
        package_name="pynacl",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="NaCl / libsodium",
        primitives=["Curve25519", "Ed25519", "XSalsa20", "Poly1305"]
    ),
    CryptoPackageMetadata(
        package_name="pyjwt",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="JWT signing / verification",
        primitives=["JWT", "HMAC", "RSA", "ECDSA"]
    ),
    CryptoPackageMetadata(
        package_name="python-jose",
        ecosystem=Ecosystem.PYPI,
        crypto_relevance="JWT + JWK + JWS",
        primitives=["JWT", "JWE", "JWS", "RSA", "ECDSA"]
    ),

    # Node.js
    CryptoPackageMetadata(
        package_name="jsonwebtoken",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="JWT implementation",
        primitives=["JWT", "HMAC", "RSA"]
    ),
    CryptoPackageMetadata(
        package_name="bcryptjs",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="bcrypt for JavaScript",
        primitives=["bcrypt"]
    ),
    CryptoPackageMetadata(
        package_name="crypto-js",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="JavaScript crypto utilities",
        primitives=["AES", "DES", "SHA-2", "HMAC"]
    ),
    CryptoPackageMetadata(
        package_name="node-forge",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="Pure-JS TLS, PKI, crypto",
        primitives=["TLS", "RSA", "AES", "X509"]
    ),
    CryptoPackageMetadata(
        package_name="jose",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="JWK / JWS / JWE",
        primitives=["JWT", "JWE", "JWS"]
    ),
    CryptoPackageMetadata(
        package_name="tweetnacl",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="NaCl for JavaScript",
        primitives=["Curve25519", "Ed25519", "XSalsa20"]
    ),
    CryptoPackageMetadata(
        package_name="elliptic",
        ecosystem=Ecosystem.NPM,
        crypto_relevance="Elliptic curve crypto",
        primitives=["ECDSA", "ECDH", "secp256k1", "ed25519"]
    ),

    # Java
    CryptoPackageMetadata(
        package_name="org.bouncycastle:bcprov-jdk15on",
        ecosystem=Ecosystem.MAVEN,
        crypto_relevance="BouncyCastle crypto provider",
        primitives=["AES", "RSA", "ECC", "SHA-2"],
        pqc_support=["SPHINCS+", "Dilithium", "Kyber", "Falcon"]  # BC has PQC
    ),
    CryptoPackageMetadata(
        package_name="org.bouncycastle:bcpqc-addon-fips",
        ecosystem=Ecosystem.MAVEN,
        crypto_relevance="BouncyCastle PQC",
        primitives=[],
        pqc_support=["ML-KEM", "ML-DSA", "SLH-DSA"]
    ),
    CryptoPackageMetadata(
        package_name="com.google.crypto.tink:tink",
        ecosystem=Ecosystem.MAVEN,
        crypto_relevance="Google Tink cryptography",
        primitives=["AES", "RSA", "ECDSA", "Ed25519", "ChaCha20-Poly1305"]
    ),

    # Go
    CryptoPackageMetadata(
        package_name="golang.org/x/crypto",
        ecosystem=Ecosystem.GO,
        crypto_relevance="Extended Go crypto",
        primitives=["argon2", "ssh", "nacl", "ed25519", "curve25519", "chacha20poly1305"]
    ),
    CryptoPackageMetadata(
        package_name="github.com/cloudflare/circl",
        ecosystem=Ecosystem.GO,
        crypto_relevance="Cloudflare Interoperable Reusable Cryptographic Library",
        primitives=["ECC", "X25519", "Ed448"],
        pqc_support=["Kyber", "Dilithium", "CSIDH", "SIDH"]
    ),
]


class CryptoRegistry:
    @classmethod
    def lookup(cls, pkg: PackageIdentity) -> Optional[CryptoPackageMetadata]:
        # Simple iteration for now
        for meta in _CRYPTO_REGISTRY:
            if meta.ecosystem == pkg.ecosystem:
                if meta.ecosystem == Ecosystem.MAVEN:
                    # pkg.name for maven includes groupId:artifactId
                    if meta.package_name == pkg.display_name:
                        return meta
                else:
                    if meta.package_name == pkg.name:
                        return meta
        return None
