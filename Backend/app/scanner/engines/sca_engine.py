"""
QuantumShield — SCA Engine (Track B, Stage 14)

Software Composition Analysis engine that parses dependency manifests
to identify known cryptographic libraries, map their versions against a
vulnerability database, and flag deprecated or unsafe crypto wrappers.

Supported manifests:
  - Python:  requirements.txt, Pipfile, pyproject.toml, setup.cfg
  - Java:   pom.xml
  - Node:   package.json, package-lock.json
  - Go:     go.mod, go.sum
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from app.scanner.models import SCAFinding, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Static data directory ────────────────────────────────────────────
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ── Known cryptographic libraries (name → relevance) ─────────────────

_CRYPTO_LIBS: dict[str, str] = {
    # Python
    "cryptography":     "General-purpose crypto (TLS, X.509, AES, RSA)",
    "pycryptodome":     "Symmetric + asymmetric encryption (AES, RSA, ECC)",
    "pycryptodomex":    "Symmetric + asymmetric encryption (AES, RSA, ECC)",
    "pyopenssl":        "OpenSSL TLS wrapper",
    "bcrypt":           "Password hashing (bcrypt)",
    "argon2-cffi":      "Password hashing (argon2)",
    "argon2":           "Password hashing (argon2)",
    "passlib":          "Multi-algorithm password hashing",
    "pynacl":           "NaCl / libsodium (Curve25519, XSalsa20)",
    "hashlib":          "Standard library hashing",
    "jwcrypto":         "JSON Web Crypto (JWK, JWE, JWS)",
    "pyjwt":            "JWT signing / verification",
    "python-jose":      "JWT + JWK + JWS",
    "paramiko":         "SSH protocol implementation",
    "pysftp":           "SFTP over SSH (paramiko wrapper)",
    "certifi":          "CA certificate bundle",
    "truststore":       "OS trust store access",
    "tls":              "TLS utilities",
    # Java
    "org.bouncycastle": "BouncyCastle crypto provider",
    "bouncycastle":     "BouncyCastle crypto provider",
    "com.google.crypto.tink": "Google Tink cryptography",
    "javax.crypto":     "JCE crypto extensions",
    # Node.js
    "jsonwebtoken":     "JWT implementation",
    "bcryptjs":         "bcrypt for JavaScript",
    "crypto-js":        "JavaScript crypto utilities",
    "node-forge":       "Pure-JS TLS, PKI, crypto",
    "jose":             "JWK / JWS / JWE",
    "tweetnacl":        "NaCl for JavaScript",
    "openpgp":          "OpenPGP encryption",
    "elliptic":         "Elliptic curve crypto",
    # Go
    "golang.org/x/crypto": "Extended Go crypto (argon2, ssh, nacl)",
}


def _load_vuln_db() -> dict[str, list[dict]]:
    """Load known-vulnerable crypto library versions from data directory."""
    path = _DATA_DIR / "crypto_vuln_db.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        logger.debug("crypto_vuln_db.json not found or invalid — using empty DB")
        return {}


class SCAEngine(ScanStage):
    """Track B — Stage 14: Software Composition Analysis for crypto libs."""

    name = "sca_engine"
    order = 21
    timeout_seconds = 30
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = ["sca_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        source_paths: list[str] = []

        raw = ctx.options.get("source_code_paths") or ctx.options.get("source_code_path")
        if isinstance(raw, str):
            source_paths = [raw]
        elif isinstance(raw, list):
            source_paths = [str(p) for p in raw]

        if not source_paths:
            logger.info("[%s] SCA: no source_code_paths configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={"sca_findings": []},
                error="No source_code_paths provided in scan options",
            )

        vuln_db = _load_vuln_db()
        all_findings: list[dict] = []

        for base_path in source_paths:
            if not os.path.isdir(base_path):
                continue
            all_findings.extend(self._scan_manifests(base_path, vuln_db))

        logger.info(
            "[%s] SCA: completed — %d crypto dependencies found",
            ctx.scan_id, len(all_findings),
        )

        return StageResult(
            status="completed",
            data={"sca_findings": all_findings},
        )

    # ── manifest walker ──────────────────────────────────────────────

    def _scan_manifests(self, base_path: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        skip = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

        for root, dirs, files in os.walk(base_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in skip]

            for filename in files:
                filepath = os.path.join(root, filename)
                lower = filename.lower()

                try:
                    if lower == "requirements.txt":
                        findings.extend(self._parse_requirements_txt(filepath, vuln_db))
                    elif lower == "pipfile":
                        findings.extend(self._parse_pipfile(filepath, vuln_db))
                    elif lower == "pyproject.toml":
                        findings.extend(self._parse_pyproject_toml(filepath, vuln_db))
                    elif lower == "pom.xml":
                        findings.extend(self._parse_pom_xml(filepath, vuln_db))
                    elif lower == "package.json":
                        findings.extend(self._parse_package_json(filepath, vuln_db))
                    elif lower == "go.mod":
                        findings.extend(self._parse_go_mod(filepath, vuln_db))
                except Exception as exc:
                    logger.debug("SCA: error parsing %s — %s", filepath, exc)

        return findings

    # ── Python: requirements.txt ─────────────────────────────────────

    def _parse_requirements_txt(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        req_pattern = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~]+\s*([0-9][0-9.a-zA-Z]*))?")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = req_pattern.match(line)
                if not m:
                    continue
                lib_name = m.group(1).lower().replace("_", "-")
                version = m.group(2)

                relevance = self._match_crypto_lib(lib_name)
                if relevance:
                    finding = self._build_finding(filepath, lib_name, version, relevance, vuln_db)
                    findings.append(finding)

        return findings

    # ── Python: Pipfile ──────────────────────────────────────────────

    def _parse_pipfile(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        in_packages = False
        pkg_pattern = re.compile(r'^([A-Za-z0-9_\-]+)\s*=\s*["\']?([^"\']+)?')

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if stripped in ("[packages]", "[dev-packages]"):
                    in_packages = True
                    continue
                if stripped.startswith("[") and in_packages:
                    in_packages = False
                    continue
                if in_packages:
                    m = pkg_pattern.match(stripped)
                    if m:
                        lib = m.group(1).lower().replace("_", "-")
                        version = m.group(2)
                        if version and version.startswith("{"):
                            version = None  # complex spec
                        relevance = self._match_crypto_lib(lib)
                        if relevance:
                            findings.append(self._build_finding(filepath, lib, version, relevance, vuln_db))

        return findings

    # ── Python: pyproject.toml ───────────────────────────────────────

    def _parse_pyproject_toml(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        dep_pattern = re.compile(r'^["\']?([A-Za-z0-9_\-]+)["\']?\s*(?:[><=!~]+\s*["\']?([0-9][0-9.a-zA-Z]*))?')

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Simple extraction of dependencies = [...] sections
        for dep_line in re.findall(r'"([^"]+)"', content):
            m = dep_pattern.match(dep_line)
            if m:
                lib = m.group(1).lower().replace("_", "-")
                version = m.group(2)
                relevance = self._match_crypto_lib(lib)
                if relevance:
                    findings.append(self._build_finding(filepath, lib, version, relevance, vuln_db))

        return findings

    # ── Java: pom.xml ────────────────────────────────────────────────

    def _parse_pom_xml(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        try:
            tree = ElementTree.parse(filepath)
            root = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}

            for dep in root.iter():
                tag = dep.tag.split("}")[-1] if "}" in dep.tag else dep.tag
                if tag != "dependency":
                    continue

                group_id = ""
                artifact_id = ""
                version = None
                for child in dep:
                    child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child_tag == "groupId":
                        group_id = (child.text or "").strip()
                    elif child_tag == "artifactId":
                        artifact_id = (child.text or "").strip()
                    elif child_tag == "version":
                        version = (child.text or "").strip()

                full_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                relevance = self._match_crypto_lib(full_name.lower())
                if not relevance:
                    relevance = self._match_crypto_lib(artifact_id.lower())
                if relevance:
                    findings.append(self._build_finding(
                        filepath, full_name, version, relevance, vuln_db
                    ))
        except ElementTree.ParseError:
            pass

        return findings

    # ── Node: package.json ───────────────────────────────────────────

    def _parse_package_json(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                pkg = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings

        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = pkg.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, ver_spec in deps.items():
                relevance = self._match_crypto_lib(name.lower())
                if relevance:
                    # Extract version number from spec like "^1.2.3" or "~2.0.0"
                    ver = re.sub(r"^[\^~>=<]+", "", str(ver_spec)) if ver_spec else None
                    findings.append(self._build_finding(filepath, name, ver, relevance, vuln_db))

        return findings

    # ── Go: go.mod ───────────────────────────────────────────────────

    def _parse_go_mod(self, filepath: str, vuln_db: dict) -> list[dict]:
        findings: list[dict] = []
        require_pattern = re.compile(r"^\s*([a-zA-Z0-9_./-]+)\s+v?([0-9][0-9.a-zA-Z\-]*)")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            in_require = False
            for line in f:
                stripped = line.strip()
                if stripped.startswith("require"):
                    in_require = True
                    continue
                if stripped == ")" and in_require:
                    in_require = False
                    continue
                if in_require or stripped.startswith("require "):
                    m = require_pattern.match(stripped)
                    if m:
                        mod = m.group(1)
                        version = m.group(2)
                        relevance = self._match_crypto_lib(mod.lower())
                        if relevance:
                            findings.append(self._build_finding(
                                filepath, mod, version, relevance, vuln_db
                            ))

        return findings

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _match_crypto_lib(name: str) -> str | None:
        """Match a library name against the known crypto lib registry."""
        lower = name.lower().replace("_", "-")
        for lib, relevance in _CRYPTO_LIBS.items():
            if lower == lib.lower() or lower.endswith(lib.lower()):
                return relevance
        return None

    @staticmethod
    def _build_finding(
        filepath: str,
        lib_name: str,
        version: str | None,
        relevance: str,
        vuln_db: dict,
    ) -> dict:
        """Create an SCAFinding dict, checking against the vuln DB."""
        is_vulnerable = False
        vuln_id = None
        severity = "info"
        latest_secure = None

        lib_lower = lib_name.lower().replace("_", "-")
        if lib_lower in vuln_db and version:
            for entry in vuln_db[lib_lower]:
                affected = entry.get("affected_versions", [])
                if version in affected or _version_in_range(version, entry):
                    is_vulnerable = True
                    vuln_id = entry.get("id", "UNKNOWN")
                    severity = entry.get("severity", "high")
                    latest_secure = entry.get("fixed_version")
                    break

        return SCAFinding(
            manifest_file=filepath,
            library_name=lib_name,
            version=version,
            latest_secure_version=latest_secure,
            is_vulnerable=is_vulnerable,
            vulnerability_id=vuln_id,
            crypto_relevance=relevance,
            severity=severity,
        ).model_dump()


def _version_in_range(version: str, entry: dict) -> bool:
    """Simple version range check (major.minor comparison)."""
    try:
        max_affected = entry.get("max_affected_version", "")
        if not max_affected:
            return False
        v_parts = [int(x) for x in re.findall(r"\d+", version)]
        m_parts = [int(x) for x in re.findall(r"\d+", max_affected)]
        # Pad to same length
        while len(v_parts) < len(m_parts):
            v_parts.append(0)
        while len(m_parts) < len(v_parts):
            m_parts.append(0)
        return v_parts <= m_parts
    except (ValueError, TypeError):
        return False
