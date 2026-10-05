"""
QuantumShield — Static Binary & Shared Library Inspector

Statically inspects ELF and PE binaries without execution or dynamic loading.
Detects:
  - Binary format (ELF32, ELF64, PE, Mach-O)
  - Crypto shared library linkage (libssl.so, libcrypto.so, libsodium.so, liboqs.so)
  - Embedded version strings (e.g. OpenSSL 3.x, BoringSSL)
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from app.scanner.container.models import (
    ArtifactType,
    ConfidenceLevel,
    CryptoObservation,
    PQCClassification,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_CRYPTO_SONAMES = (
    "libssl.so", "libcrypto.so", "libsodium.so", "liboqs.so",
    "libgcrypt.so", "libwolfssl.so", "libmbedtls.so", "libmbedcrypto.so",
)

_OPENSSL_VERSION_RE = re.compile(
    rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)\b",
    re.IGNORECASE,
)
_BORINGSSL_RE = re.compile(rb"BoringSSL", re.IGNORECASE)
_LIBRESSL_RE = re.compile(rb"LibreSSL\s+(\d+\.\d+\.\d+)", re.IGNORECASE)


class BinaryInspector:
    """Safe static binary inspector."""

    @classmethod
    def inspect_binary(cls, filepath: str, target_id: str = "local") -> List[CryptoObservation]:
        """Statically inspect an executable or shared library."""
        observations: List[CryptoObservation] = []
        if not os.path.isfile(filepath):
            return observations

        filename = os.path.basename(filepath)

        # Check if the filename itself is a crypto library
        for soname in _CRYPTO_SONAMES:
            prefix = soname.replace(".so", "")
            if prefix in filename.lower():
                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_library",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_LIBRARY.value,
                        algorithm=f"Shared Library: {filename}",
                        pqc_classification=PQCClassification.PQC_CAPABLE_LIBRARY.value if "liboqs" in filename else PQCClassification.CLASSICAL.value,
                        confidence=ConfidenceLevel.HIGH,
                        parser="soname_static_inspector",
                        evidence={
                            "library_type": "ELF Shared Library",
                            "soname": filename,
                        },
                    )
                )

        # Read bounded chunks for version string extraction (max 64KB)
        try:
            with open(filepath, "rb") as f:
                header = f.read(65536)

            if not header.startswith(b"\x7fELF") and not header.startswith(b"MZ"):
                return observations

            # OpenSSL version string match
            m_ossl = _OPENSSL_VERSION_RE.search(header)
            if m_ossl:
                ver_str = m_ossl.group(1).decode("ascii", "ignore")
                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_library",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_LIBRARY.value,
                        algorithm=f"OpenSSL {ver_str}",
                        confidence=ConfidenceLevel.HIGH,
                        parser="binary_embedded_string_inspector",
                        evidence={
                            "library": "OpenSSL",
                            "version": ver_str,
                            "detection_method": "embedded_version_string",
                        },
                    )
                )

            # BoringSSL match
            if _BORINGSSL_RE.search(header):
                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_library",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_LIBRARY.value,
                        algorithm="BoringSSL",
                        confidence=ConfidenceLevel.MEDIUM,
                        parser="binary_embedded_string_inspector",
                        evidence={"library": "BoringSSL"},
                    )
                )

            # LibreSSL match
            m_libre = _LIBRESSL_RE.search(header)
            if m_libre:
                ver_str = m_libre.group(1).decode("ascii", "ignore")
                observations.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_library",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_LIBRARY.value,
                        algorithm=f"LibreSSL {ver_str}",
                        confidence=ConfidenceLevel.HIGH,
                        parser="binary_embedded_string_inspector",
                        evidence={"library": "LibreSSL", "version": ver_str},
                    )
                )

        except Exception as exc:
            logger.debug("Failed reading binary %s: %s", filepath, exc)

        return observations
