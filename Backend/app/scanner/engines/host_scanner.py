"""
QuantumShield — Infrastructure & Host Scanner (Track B, Stage 15)

Scans server filesystems, Dockerfiles, and IaC templates to discover
internal cryptographic material:

  1. Certificate files (.pem, .crt, .jks, .p12) → parsed via cryptography.x509
  2. Daemon configs (sshd_config, nginx.conf, apache, haproxy) → cipher/kex extraction
  3. Dockerfiles / docker-compose → exposed crypto-relevant settings
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.scanner.models import (
    HostConfigFinding,
    InternalCertFinding,
    StageResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Certificate extensions to search for ─────────────────────────────

_CERT_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".key"})

# ── Config files to parse ────────────────────────────────────────────

_CONFIG_FILENAMES = frozenset({
    "sshd_config", "ssh_config",
    "nginx.conf",
    "httpd.conf", "apache2.conf", "ssl.conf",
    "haproxy.cfg",
    "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml",
    "redis.conf",
    "postgresql.conf",
    "my.cnf", "mysql.cnf",
})

_SKIP_DIRS = frozenset({
    "__pycache__", "node_modules", ".git", ".venv", "venv",
    "env", "dist", "build", ".tox", "site-packages",
})

# ── SSH config cipher/kex patterns ───────────────────────────────────

_SSH_CIPHER_KEYS = frozenset({
    "ciphers", "kexalgorithms", "macs", "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
})

# ── Nginx / Apache SSL patterns ──────────────────────────────────────

_NGINX_SSL_PATTERNS = {
    "ssl_protocols": re.compile(r"ssl_protocols\s+([^;]+);", re.IGNORECASE),
    "ssl_ciphers": re.compile(r"ssl_ciphers\s+['\"]?([^;'\"]+)['\"]?;", re.IGNORECASE),
    "ssl_certificate": re.compile(r"ssl_certificate\s+([^;]+);", re.IGNORECASE),
    "ssl_certificate_key": re.compile(r"ssl_certificate_key\s+([^;]+);", re.IGNORECASE),
}

_APACHE_SSL_PATTERNS = {
    "SSLProtocol": re.compile(r"SSLProtocol\s+(.+)$", re.IGNORECASE | re.MULTILINE),
    "SSLCipherSuite": re.compile(r"SSLCipherSuite\s+(.+)$", re.IGNORECASE | re.MULTILINE),
    "SSLCertificateFile": re.compile(r"SSLCertificateFile\s+(.+)$", re.IGNORECASE | re.MULTILINE),
}


class HostScannerEngine(ScanStage):
    """Track B — Stage 15: Infrastructure & Host configuration scanner."""

    name = "host_scanner"
    order = 22
    timeout_seconds = 45
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = ["host_config_findings", "internal_certificates"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        scan_paths: list[str] = []

        raw = ctx.options.get("host_scan_paths") or ctx.options.get("source_code_paths") or ctx.options.get("source_code_path")
        if isinstance(raw, str):
            scan_paths = [raw]
        elif isinstance(raw, list):
            scan_paths = [str(p) for p in raw]

        if not scan_paths:
            logger.info("[%s] HostScanner: no paths configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={"host_config_findings": [], "internal_certificates": []},
                error="No host_scan_paths provided in scan options",
            )

        all_certs: list[dict] = []
        all_configs: list[dict] = []

        for base_path in scan_paths:
            if not os.path.exists(base_path):
                continue
            certs, configs = self._scan_path(base_path)
            all_certs.extend(certs)
            all_configs.extend(configs)

        logger.info(
            "[%s] HostScanner: found %d internal certificates, %d config findings",
            ctx.scan_id, len(all_certs), len(all_configs),
        )

        return StageResult(
            status="completed",
            data={
                "internal_certificates": all_certs,
                "host_config_findings": all_configs,
            },
        )

    # ── filesystem walker ────────────────────────────────────────────

    def _scan_path(self, base_path: str) -> tuple[list[dict], list[dict]]:
        certs: list[dict] = []
        configs: list[dict] = []

        if os.path.isfile(base_path):
            # Single file
            filename = os.path.basename(base_path)
            ext = os.path.splitext(filename)[1].lower()
            if ext in _CERT_EXTENSIONS:
                cert = self._parse_certificate_file(base_path)
                if cert:
                    certs.append(cert)
            if filename.lower() in _CONFIG_FILENAMES:
                configs.extend(self._parse_config_file(base_path, filename))
            return certs, configs

        for root, dirs, files in os.walk(base_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

            for filename in files:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()

                # Certificate files
                if ext in _CERT_EXTENSIONS:
                    cert = self._parse_certificate_file(filepath)
                    if cert:
                        certs.append(cert)

                # Config files
                if filename.lower() in _CONFIG_FILENAMES:
                    configs.extend(self._parse_config_file(filepath, filename))

                # Also check for common config paths
                rel = os.path.relpath(filepath, base_path).replace("\\", "/")
                if any(p in rel for p in ("/etc/ssh/", "/etc/nginx/", "/etc/apache2/", "/etc/haproxy/")):
                    configs.extend(self._parse_config_file(filepath, filename))

        return certs, configs

    # ── certificate parser ───────────────────────────────────────────

    def _parse_certificate_file(self, filepath: str) -> dict | None:
        """Parse a certificate file using cryptography.x509."""
        ext = os.path.splitext(filepath)[1].lower()

        # Skip private key files (we note them but don't parse as certs)
        if ext == ".key":
            return InternalCertFinding(
                file_path=filepath,
                file_extension=ext,
                subject_cn="[Private Key File]",
            ).model_dump()

        # Skip Java keystores (binary, need special handling)
        if ext in (".jks", ".p12", ".pfx"):
            return InternalCertFinding(
                file_path=filepath,
                file_extension=ext,
                subject_cn=f"[{ext.upper()} keystore — binary parsing not available]",
            ).model_dump()

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, rsa

            with open(filepath, "rb") as f:
                raw = f.read()

            # Try PEM first, then DER
            cert = None
            if b"-----BEGIN CERTIFICATE-----" in raw:
                cert = x509.load_pem_x509_certificate(raw)
            elif ext in (".der", ".cer", ".crt"):
                try:
                    cert = x509.load_der_x509_certificate(raw)
                except Exception:
                    pass

            if cert is None:
                return InternalCertFinding(
                    file_path=filepath,
                    file_extension=ext,
                    subject_cn="[Unparseable certificate]",
                ).model_dump()

            # Extract attributes
            now = datetime.now(timezone.utc)
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_left = (not_after - now).days

            # Key type/size
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                key_type, key_size = "RSA", pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_type, key_size = "EC", pub.key_size
            else:
                key_type, key_size = "unknown", None

            # Subject/Issuer CN extraction
            subject_cn = self._extract_cn(cert.subject)
            issuer_cn = self._extract_cn(cert.issuer)

            # Signature algorithm
            try:
                sig_alg = cert.signature_algorithm_oid._name
            except AttributeError:
                sig_alg = cert.signature_algorithm_oid.dotted_string

            return InternalCertFinding(
                file_path=filepath,
                file_extension=ext,
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                not_valid_before=not_before.isoformat(),
                not_valid_after=not_after.isoformat(),
                key_type=key_type,
                key_size=key_size,
                sig_algorithm=sig_alg,
                sig_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
                fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(":"),
                expired=days_left < 0,
                days_until_expiry=days_left,
                serial=str(cert.serial_number),
            ).model_dump()

        except ImportError:
            logger.warning("cryptography library not available for cert parsing")
            return InternalCertFinding(
                file_path=filepath,
                file_extension=ext,
                subject_cn="[cryptography lib unavailable]",
            ).model_dump()
        except Exception as exc:
            logger.debug("Failed to parse certificate %s: %s", filepath, exc)
            return InternalCertFinding(
                file_path=filepath,
                file_extension=ext,
                subject_cn=f"[Parse error: {str(exc)[:60]}]",
            ).model_dump()

    @staticmethod
    def _extract_cn(name) -> str:
        """Extract Common Name from an x509 Name object."""
        try:
            from cryptography.x509.oid import NameOID
            cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cns:
                return cns[0].value
        except Exception:
            pass
        try:
            return name.rfc4514_string()[:64]
        except Exception:
            return "unknown"

    # ── config file parser ───────────────────────────────────────────

    def _parse_config_file(self, filepath: str, filename: str) -> list[dict]:
        findings: list[dict] = []
        lower = filename.lower()

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return findings

        if lower in ("sshd_config", "ssh_config"):
            findings.extend(self._parse_ssh_config(filepath, content))
        elif "nginx" in lower:
            findings.extend(self._parse_nginx_config(filepath, content))
        elif lower in ("httpd.conf", "apache2.conf", "ssl.conf"):
            findings.extend(self._parse_apache_config(filepath, content))
        elif "haproxy" in lower:
            findings.extend(self._parse_haproxy_config(filepath, content))
        elif lower.startswith("dockerfile"):
            findings.extend(self._parse_dockerfile(filepath, content))
        elif "redis" in lower:
            findings.extend(self._parse_redis_config(filepath, content))
        elif "postgres" in lower:
            findings.extend(self._parse_postgres_config(filepath, content))

        return findings

    # ── SSH ───────────────────────────────────────────────────────────

    def _parse_ssh_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for line in content.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1]
            if key in _SSH_CIPHER_KEYS:
                algos = [a.strip() for a in value.split(",") if a.strip()]
                risk = "info"
                # Flag weak algorithms
                weak = {"3des-cbc", "arcfour", "arcfour128", "arcfour256",
                        "diffie-hellman-group1-sha1", "hmac-md5", "hmac-sha1"}
                if any(a.lower() in weak for a in algos):
                    risk = "high"

                findings.append(HostConfigFinding(
                    config_file=filepath,
                    daemon="sshd",
                    setting_name=key,
                    setting_value=value,
                    algorithms_extracted=algos,
                    risk_level=risk,
                ).model_dump())

        return findings

    # ── Nginx ────────────────────────────────────────────────────────

    def _parse_nginx_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for setting, pattern in _NGINX_SSL_PATTERNS.items():
            for m in pattern.finditer(content):
                value = m.group(1).strip()
                algos = [a.strip() for a in re.split(r"[\s:]+", value) if a.strip()]
                risk = "info"
                if setting == "ssl_protocols":
                    if any(p.lower() in ("sslv3", "tlsv1", "tlsv1.1") for p in algos):
                        risk = "high"
                elif setting == "ssl_ciphers":
                    if any(c.lower() in ("rc4", "des", "3des", "null", "export") for c in algos):
                        risk = "critical"

                findings.append(HostConfigFinding(
                    config_file=filepath,
                    daemon="nginx",
                    setting_name=setting,
                    setting_value=value,
                    algorithms_extracted=algos,
                    risk_level=risk,
                ).model_dump())

        return findings

    # ── Apache ───────────────────────────────────────────────────────

    def _parse_apache_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for setting, pattern in _APACHE_SSL_PATTERNS.items():
            for m in pattern.finditer(content):
                value = m.group(1).strip()
                algos = [a.strip() for a in re.split(r"[\s:]+", value) if a.strip()]
                risk = "info"
                if setting == "SSLProtocol":
                    if any(p.lower() in ("sslv3", "tlsv1", "tlsv1.1", "-all") for p in algos):
                        risk = "high"
                findings.append(HostConfigFinding(
                    config_file=filepath,
                    daemon="apache",
                    setting_name=setting,
                    setting_value=value,
                    algorithms_extracted=algos,
                    risk_level=risk,
                ).model_dump())

        return findings

    # ── HAProxy ──────────────────────────────────────────────────────

    def _parse_haproxy_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        ssl_pattern = re.compile(r"ssl-default-bind-(?:ciphers|ciphersuites|options)\s+(.+)$",
                                  re.IGNORECASE | re.MULTILINE)
        for m in ssl_pattern.finditer(content):
            value = m.group(1).strip()
            algos = [a.strip() for a in value.split(":") if a.strip()]
            findings.append(HostConfigFinding(
                config_file=filepath,
                daemon="haproxy",
                setting_name="ssl-default-bind",
                setting_value=value,
                algorithms_extracted=algos,
                risk_level="info",
            ).model_dump())
        return findings

    # ── Dockerfile ───────────────────────────────────────────────────

    def _parse_dockerfile(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        # Detect exposed crypto-relevant env vars or insecure settings
        env_pattern = re.compile(
            r"ENV\s+(JWT_SECRET|SECRET_KEY|API_KEY|SSL_CERT|TLS_KEY)\s*[=\s]+(.+)$",
            re.IGNORECASE | re.MULTILINE,
        )
        for m in env_pattern.finditer(content):
            findings.append(HostConfigFinding(
                config_file=filepath,
                daemon="docker",
                setting_name=m.group(1),
                setting_value=m.group(2).strip()[:40] + "…",
                risk_level="high",
            ).model_dump())

        # Detect OpenSSL install (version might be outdated)
        if re.search(r"(?:apt-get|apk|yum)\s+install.*openssl", content, re.IGNORECASE):
            findings.append(HostConfigFinding(
                config_file=filepath,
                daemon="docker",
                setting_name="openssl_install",
                setting_value="OpenSSL installed via package manager",
                risk_level="info",
            ).model_dump())

        return findings

    # ── Redis ────────────────────────────────────────────────────────

    def _parse_redis_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for key in ("tls-cert-file", "tls-key-file", "tls-protocols", "tls-ciphers"):
            pattern = re.compile(rf"^{re.escape(key)}\s+(.+)$", re.MULTILINE | re.IGNORECASE)
            for m in pattern.finditer(content):
                findings.append(HostConfigFinding(
                    config_file=filepath,
                    daemon="redis",
                    setting_name=key,
                    setting_value=m.group(1).strip(),
                    risk_level="info",
                ).model_dump())
        return findings

    # ── PostgreSQL ───────────────────────────────────────────────────

    def _parse_postgres_config(self, filepath: str, content: str) -> list[dict]:
        findings: list[dict] = []
        for key in ("ssl", "ssl_cert_file", "ssl_key_file", "ssl_ciphers", "ssl_min_protocol_version"):
            pattern = re.compile(rf"^{re.escape(key)}\s*=\s*'?([^'\n]+)'?", re.MULTILINE | re.IGNORECASE)
            for m in pattern.finditer(content):
                findings.append(HostConfigFinding(
                    config_file=filepath,
                    daemon="postgresql",
                    setting_name=key,
                    setting_value=m.group(1).strip(),
                    risk_level="info",
                ).model_dump())
        return findings
