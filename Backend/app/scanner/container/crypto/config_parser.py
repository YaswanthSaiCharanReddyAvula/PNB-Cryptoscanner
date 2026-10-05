"""
QuantumShield — Cryptographic Configuration & Secret Analyzer

Statically parses daemon, framework, and system configuration files for crypto settings.
Extracts:
  - TLS versions and supported protocols
  - Ciphers, KEX algorithms, and MACs (SSH, Nginx, Apache, OpenSSL)
  - Key and certificate file path references
  - Crypto-related environment variables (strictly redacted)
  - Java security disabled algorithm policies
"""

from __future__ import annotations

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

# Patterns for Daemon Configurations
_SSH_CIPHER_KEYS = frozenset({
    "ciphers", "kexalgorithms", "macs", "hostkeyalgorithms",
    "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes",
})

_NGINX_PATTERNS = {
    "ssl_protocols": re.compile(r"ssl_protocols\s+([^;]+);", re.IGNORECASE),
    "ssl_ciphers": re.compile(r"ssl_ciphers\s+['\"]?([^;'\"]+)['\"]?;", re.IGNORECASE),
    "ssl_certificate": re.compile(r"ssl_certificate\s+([^;]+);", re.IGNORECASE),
    "ssl_certificate_key": re.compile(r"ssl_certificate_key\s+([^;]+);", re.IGNORECASE),
}

_APACHE_PATTERNS = {
    "SSLProtocol": re.compile(r"SSLProtocol\s+(.+)$", re.IGNORECASE | re.MULTILINE),
    "SSLCipherSuite": re.compile(r"SSLCipherSuite\s+(.+)$", re.IGNORECASE | re.MULTILINE),
    "SSLCertificateFile": re.compile(r"SSLCertificateFile\s+(.+)$", re.IGNORECASE | re.MULTILINE),
    "SSLCertificateKeyFile": re.compile(r"SSLCertificateKeyFile\s+(.+)$", re.IGNORECASE | re.MULTILINE),
}

_OPENSSL_PATTERNS = {
    "CipherString": re.compile(r"CipherString\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "MinProtocol": re.compile(r"MinProtocol\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "MaxProtocol": re.compile(r"MaxProtocol\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}

_CRYPTO_ENV_VAR_NAMES = frozenset({
    "SSL_CERT_FILE", "SSL_CERT_DIR", "PRIVATE_KEY_PATH", "TLS_KEY", "TLS_CERT",
    "KMS_KEY_ID", "HSM_SLOT", "AWS_KMS_KEY_ID", "VAULT_TOKEN", "CERT_PATH",
})


class ConfigParser:
    """Safe static parser for cryptographic configurations."""

    @classmethod
    def parse_file(cls, filepath: str, target_id: str = "local") -> List[CryptoObservation]:
        """Inspect file for crypto configurations."""
        observations: List[CryptoObservation] = []
        if not os.path.isfile(filepath):
            return observations

        filename = os.path.basename(filepath).lower()
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return observations

        if not content:
            return observations

        # 1. SSH Config (sshd_config / ssh_config)
        if "sshd_config" in filename or "ssh_config" in filename:
            observations.extend(cls._parse_ssh_config(content, filepath, target_id))

        # 2. Nginx Config (nginx.conf or *.conf with http context)
        elif "nginx" in filename or "nginx" in filepath.replace("\\", "/").lower():
            observations.extend(cls._parse_nginx_config(content, filepath, target_id))

        # 3. Apache Config (httpd.conf, ssl.conf, apache2.conf)
        elif any(k in filename for k in ("httpd", "apache", "ssl.conf")):
            observations.extend(cls._parse_apache_config(content, filepath, target_id))

        # 4. OpenSSL Config (openssl.cnf)
        elif "openssl" in filename:
            observations.extend(cls._parse_openssl_config(content, filepath, target_id))

        # 5. Java Security (java.security)
        elif "java.security" in filename:
            observations.extend(cls._parse_java_security(content, filepath, target_id))

        # 6. Dockerfile / docker-compose (Crypto ENV or volumes)
        elif "dockerfile" in filename or "docker-compose" in filename:
            observations.extend(cls._parse_docker_config(content, filepath, target_id))

        return observations

    @classmethod
    def _parse_ssh_config(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract SSH ciphers and kex algorithms."""
        obs_list = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, val = parts[0].lower(), parts[1].strip()
                if key in _SSH_CIPHER_KEYS:
                    algos = [a.strip() for a in val.split(",") if a.strip()]
                    obs_list.append(
                        CryptoObservation(
                            target_id=target_id,
                            target_type="crypto_config",
                            file_path=filepath,
                            artifact_type=ArtifactType.CRYPTO_CONFIG.value,
                            algorithm="SSH Config",
                            confidence=ConfidenceLevel.HIGH,
                            parser="ssh_config_parser",
                            evidence={
                                "daemon": "sshd",
                                "setting_name": key,
                                "setting_value": val,
                                "algorithms_extracted": algos,
                            },
                        )
                    )
        return obs_list

    @classmethod
    def _parse_nginx_config(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract Nginx SSL directives."""
        obs_list = []
        for directive, pattern in _NGINX_PATTERNS.items():
            for match in pattern.finditer(content):
                val = match.group(1).strip()
                extracted = [x.strip() for x in val.split() if x.strip()] if ":" not in val else [x.strip() for x in val.split(":") if x.strip()]
                obs_list.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_config",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_CONFIG.value,
                        algorithm="Nginx TLS Config",
                        confidence=ConfidenceLevel.HIGH,
                        parser="nginx_config_parser",
                        evidence={
                            "daemon": "nginx",
                            "setting_name": directive,
                            "setting_value": val,
                            "algorithms_extracted": extracted,
                        },
                    )
                )
        return obs_list

    @classmethod
    def _parse_apache_config(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract Apache SSL directives."""
        obs_list = []
        for directive, pattern in _APACHE_PATTERNS.items():
            for match in pattern.finditer(content):
                val = match.group(1).strip()
                extracted = [x.strip() for x in re.split(r"[\s:]+", val) if x.strip()]
                obs_list.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_config",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_CONFIG.value,
                        algorithm="Apache TLS Config",
                        confidence=ConfidenceLevel.HIGH,
                        parser="apache_config_parser",
                        evidence={
                            "daemon": "apache",
                            "setting_name": directive,
                            "setting_value": val,
                            "algorithms_extracted": extracted,
                        },
                    )
                )
        return obs_list

    @classmethod
    def _parse_openssl_config(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract OpenSSL configuration directives."""
        obs_list = []
        for directive, pattern in _OPENSSL_PATTERNS.items():
            for match in pattern.finditer(content):
                val = match.group(1).strip()
                obs_list.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_config",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_CONFIG.value,
                        algorithm="OpenSSL Config",
                        confidence=ConfidenceLevel.HIGH,
                        parser="openssl_cnf_parser",
                        evidence={
                            "daemon": "openssl",
                            "setting_name": directive,
                            "setting_value": val,
                        },
                    )
                )
        return obs_list

    @classmethod
    def _parse_java_security(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Extract Java security policies."""
        obs_list = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("jdk.tls.disabledAlgorithms="):
                val = line.split("=", 1)[1].strip()
                disabled = [x.strip() for x in val.split(",") if x.strip()]
                obs_list.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_config",
                        file_path=filepath,
                        artifact_type=ArtifactType.CRYPTO_CONFIG.value,
                        algorithm="Java Security Policy",
                        confidence=ConfidenceLevel.HIGH,
                        parser="java_security_parser",
                        evidence={
                            "daemon": "java",
                            "setting_name": "jdk.tls.disabledAlgorithms",
                            "disabled_algorithms": disabled,
                        },
                    )
                )
        return obs_list

    @classmethod
    def _parse_docker_config(cls, content: str, filepath: str, target_id: str) -> List[CryptoObservation]:
        """Inspect Dockerfile or docker-compose for crypto env vars."""
        obs_list = []
        for line in content.splitlines():
            line = line.strip()
            for env_var in _CRYPTO_ENV_VAR_NAMES:
                if env_var in line:
                    obs_list.append(
                        CryptoObservation(
                            target_id=target_id,
                            target_type="crypto_env_var",
                            file_path=filepath,
                            artifact_type=ArtifactType.CRYPTO_ENV_VAR.value,
                            algorithm="Environment Variable",
                            confidence=ConfidenceLevel.MEDIUM,
                            parser="docker_env_parser",
                            evidence={
                                "variable_name": env_var,
                                "source": "Dockerfile/docker-compose",
                                "redacted_presence": f"[{env_var} defined]",
                            },
                        )
                    )
        return obs_list

    @classmethod
    def inspect_env_variables(cls, env_list: List[str], target_id: str) -> List[CryptoObservation]:
        """Inspect container environment variables without recording secret values."""
        obs_list = []
        for item in env_list:
            if "=" in item:
                k, v = item.split("=", 1)
            else:
                k, v = item, ""
            k_upper = k.strip().upper()
            if k_upper in _CRYPTO_ENV_VAR_NAMES or any(token in k_upper for token in ("TLS_", "SSL_", "CERT_", "KEY_FILE", "KEY_PATH")):
                # Redact value
                redacted = f"[{len(v)}-char secret redacted]" if v else "[present]"
                obs_list.append(
                    CryptoObservation(
                        target_id=target_id,
                        target_type="crypto_env_var",
                        file_path="container_environment",
                        artifact_type=ArtifactType.CRYPTO_ENV_VAR.value,
                        algorithm="Environment Variable",
                        confidence=ConfidenceLevel.HIGH,
                        parser="container_env_parser",
                        evidence={
                            "variable_name": k,
                            "redacted_value_presence": redacted,
                        },
                    )
                )
        return obs_list
