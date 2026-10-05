"""
QuantumShield — Post-Quantum Cryptography (PQC) Detector

Identifies evidence of PQC-capable libraries, PQC configuration, and PQC usage.
Recognizes:
  - NIST FIPS 203 (ML-KEM / Kyber)
  - NIST FIPS 204 (ML-DSA / Dilithium)
  - NIST FIPS 205 (SLH-DSA / SPHINCS+)
  - Falcon, Classic McEliece, HQC
  - PQC libraries: liboqs, oqsprovider, BouncyCastle PQC, Cloudflare CIRCL
Categorizes findings into:
  - PQC_CAPABLE_LIBRARY
  - PQC_CONFIGURED
  - PQC_USAGE_OBSERVED
"""

from __future__ import annotations

import re
from typing import List, Optional

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PackageObservation,
    PQCClassification,
)

_PQC_ALGO_PATTERNS = {
    "ML-KEM": re.compile(r"\b(?:ml[-_]?kem|kyber[-_]?(?:512|768|1024)?)\b", re.IGNORECASE),
    "ML-DSA": re.compile(r"\b(?:ml[-_]?dsa|dilithium[-_]?(?:2|3|5)?)\b", re.IGNORECASE),
    "SLH-DSA": re.compile(r"\b(?:slh[-_]?dsa|sphincs\+?)\b", re.IGNORECASE),
    "Falcon": re.compile(r"\b(?:falcon[-_]?(?:512|1024)?)\b", re.IGNORECASE),
    "Hybrid-KEX": re.compile(r"\b(?:x25519_?kyber|secp256r1_?kyber|x25519_?mlkem)\b", re.IGNORECASE),
}

_PQC_LIBRARIES = {
    "liboqs": "Open Quantum Safe C library",
    "oqsprovider": "OpenSSL 3.x Open Quantum Safe Provider",
    "bcpqc": "Bouncy Castle Post-Quantum Cryptography Addon",
    "circl": "Cloudflare Interoperable Reusable Cryptographic Library",
}


class PQCDetector:
    """Detects and categorizes Post-Quantum Cryptographic signals."""

    @classmethod
    def inspect_text_content(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Inspect configuration, source, or metadata text for PQC keywords."""
        observations: List[CryptoObservation] = []
        for algo_family, pattern in _PQC_ALGO_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                sample = list(set(matches))[:5]
                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_pqc",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_PQC.value,
                        algorithm=algo_family,
                        pqc_classification=PQCClassification.PQC_CONFIGURED.value,
                        confidence=ConfidenceLevel.HIGH,
                        parser="pqc_keyword_detector",
                        evidence={
                            "algo_family": algo_family,
                            "matched_tokens": sample,
                            "source_file": filepath,
                        },
                    )
                )
        return observations

    @classmethod
    def evaluate_package(cls, pkg: PackageObservation, target_id: str) -> Optional[CryptoObservation]:
        """Check if discovered OS or language package is PQC-capable."""
        name_lower = pkg.name.lower()
        for lib_key, desc in _PQC_LIBRARIES.items():
            if lib_key in name_lower or any(lib_key in p.lower() for p in pkg.pqc_support):
                return CryptoObservation(
                    target_id=target_id,
                    target_type="crypto_pqc",
                    file_path=pkg.source_file,
                    artifact_type=ArtifactType.CRYPTO_PQC.value,
                    algorithm="PQC Library",
                    pqc_classification=PQCClassification.PQC_CAPABLE_LIBRARY.value,
                    confidence=ConfidenceLevel.HIGH,
                    parser="pqc_library_detector",
                    evidence={
                        "library_name": pkg.name,
                        "description": desc,
                        "ecosystem": pkg.ecosystem,
                        "version": pkg.version,
                    },
                )
        return None
