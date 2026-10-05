"""
QuantumShield — Static File Type Classifier

Classifies files into artifact categories without executing them.
Uses file magic headers, structural markers, and path heuristics.
"""

from __future__ import annotations

import os
from typing import Tuple

# Magic bytes signatures
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_JKS_MAGIC = b"\xfe\xed\xfe\xed"
_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
_TAR_USTAR_MAGIC = b"ustar"

_PEM_CERT_MARKER = b"-----BEGIN CERTIFICATE-----"
_PEM_PRIVKEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
)
_PEM_PUBKEY_MARKERS = (
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN EC PUBLIC KEY-----",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ecdsa-sha2-",
)

_CONFIG_BASENAMES = frozenset({
    "sshd_config", "ssh_config",
    "nginx.conf",
    "httpd.conf", "apache2.conf", "ssl.conf",
    "haproxy.cfg",
    "openssl.cnf", "openssl.conf",
    "java.security",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "redis.conf", "postgresql.conf", "my.cnf", "mysql.cnf",
})

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".java", ".kt", ".scala", ".go", ".rs",
    ".js", ".jsx", ".ts", ".tsx", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".cs", ".php", ".rb", ".swift",
})

_DOC_EXTENSIONS = frozenset({
    ".md", ".rst", ".txt", ".pdf", ".html", ".htm",
    ".doc", ".docx", ".license", ".changelog",
})


class FileClassifier:
    """Safe, static classifier for filesystem artifacts."""

    @classmethod
    def classify(cls, file_path: str, size: int) -> Tuple[str, dict]:
        """
        Classify file based on path heuristics and initial header bytes.
        Returns (classified_type, extra_metadata).
        """
        basename = os.path.basename(file_path).lower()
        ext = os.path.splitext(basename)[1].lower()

        # Check config basenames first
        if basename in _CONFIG_BASENAMES or any(basename.startswith(cfg) for cfg in ("nginx", "httpd", "apache", "sshd_config")):
            return "crypto_config", {"config_type": basename}

        # Check OS package metadata paths
        norm_path = file_path.replace("\\", "/").lower()
        if norm_path.endswith("/var/lib/dpkg/status") or norm_path.endswith("/var/lib/dpkg/status.d"):
            return "package_metadata", {"ecosystem": "dpkg"}
        if "/lib/apk/db/installed" in norm_path or "/etc/apk/world" in norm_path:
            return "package_metadata", {"ecosystem": "apk"}
        if "/var/lib/rpm/packages" in norm_path or norm_path.endswith("/rpmdb"):
            return "package_metadata", {"ecosystem": "rpm"}

        # Language manifest basenames
        if basename in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            return "package_metadata", {"ecosystem": "npm"}
        if basename in ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "poetry.lock"):
            return "package_metadata", {"ecosystem": "pypi"}
        if basename in ("pom.xml", "build.gradle", "build.gradle.kts"):
            return "package_metadata", {"ecosystem": "maven"}
        if basename in ("go.mod", "go.sum"):
            return "package_metadata", {"ecosystem": "go"}
        if basename in ("cargo.toml", "cargo.lock"):
            return "package_metadata", {"ecosystem": "rust"}

        # Source code extensions
        if ext in _SOURCE_EXTENSIONS:
            return "source_code", {"language": ext.lstrip(".")}

        # Documentation extensions
        if ext in _DOC_EXTENSIONS:
            return "documentation", {}

        # Shared library extensions
        if ext in (".so", ".dll", ".dylib") or ".so." in basename:
            return "shared_library", {}

        # If file is empty or unreadable
        if size == 0:
            return "empty", {}

        # Read small header for magic inspection (max 2048 bytes)
        header = b""
        try:
            with open(file_path, "rb") as f:
                header = f.read(min(size, 2048))
        except Exception:
            return "unreadable", {}

        # Check Keystores
        if header.startswith(_JKS_MAGIC):
            return "keystore", {"keystore_format": "JKS"}
        if ext in (".p12", ".pfx") or basename.endswith(".p12") or basename.endswith(".pfx"):
            return "keystore", {"keystore_format": "PKCS12"}
        if ext == ".jks":
            return "keystore", {"keystore_format": "JKS"}

        # Check PEM Certificate
        if _PEM_CERT_MARKER in header:
            return "certificate", {"format": "PEM"}

        # Check PEM Private Keys
        for marker in _PEM_PRIVKEY_MARKERS:
            if marker in header:
                return "private_key_candidate", {"format": "PEM", "marker": marker.decode("ascii", "ignore")}

        # Check PEM Public Keys
        for marker in _PEM_PUBKEY_MARKERS:
            if marker in header:
                return "public_key", {"format": "PEM"}

        # Check DER X.509 Certificate (starts with ASN.1 SEQUENCE 0x30 0x82...)
        if ext in (".der", ".cer", ".crt") and len(header) > 4:
            if header[0] == 0x30 and header[1] in (0x82, 0x83, 0x84):
                return "certificate", {"format": "DER"}

        # Check Executables / Binaries
        if header.startswith(_ELF_MAGIC):
            return "binary", {"format": "ELF"}
        if header.startswith(_PE_MAGIC):
            return "binary", {"format": "PE"}

        # Check Archives
        if header.startswith(_GZIP_MAGIC) or header.startswith(_ZIP_MAGIC) or ext in (".tar", ".tgz", ".tar.gz", ".zip"):
            return "archive", {}

        # Fallback extension heuristics
        if ext in (".crt", ".cer", ".pem"):
            return "certificate", {"format": "unknown"}
        if ext == ".key":
            return "private_key_candidate", {"format": "unknown"}

        return "unknown", {}
