"""
QuantumShield — SAST Crypto Engine (Track B, Stage 13)

Static analysis of application source code to discover Data-in-Use and
Data-at-Rest cryptographic primitives.  Uses Python's AST module for
Python files, and strict regex patterns for Java / JavaScript / Go /
generic config files.

Detects:
  1. Cryptographic library imports
  2. Hashing functions used for passwords (bcrypt, argon2, PBKDF2)
  3. Symmetric encryption logic (AES, ChaCha20, Fernet)
  4. Hardcoded secrets (JWT secrets, static API keys, IVs)
"""

from __future__ import annotations

import ast
import os
import re
from typing import Any

from app.scanner.models import SASTFinding, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Target crypto libraries (per-language) ───────────────────────────

_PYTHON_CRYPTO_MODULES = frozenset({
    "hashlib", "hmac", "secrets",
    "cryptography", "Crypto", "Cryptodome",
    "bcrypt", "argon2", "passlib", "nacl", "pynacl",
    "jwt", "jose", "jwcrypto",
    "ssl", "OpenSSL",
    "fernet",
})

_JAVA_CRYPTO_PATTERNS = [
    re.compile(r"import\s+(javax\.crypto\.[A-Za-z.]+)", re.MULTILINE),
    re.compile(r"import\s+(java\.security\.[A-Za-z.]+)", re.MULTILINE),
    re.compile(r"import\s+(org\.bouncycastle\.[A-Za-z.]+)", re.MULTILINE),
]

_JS_CRYPTO_PATTERNS = [
    re.compile(r"""(?:require|import)\s*\(?\s*['"](?:crypto|node:crypto|bcrypt|argon2|jsonwebtoken|jose|tweetnacl|crypto-js)['"]"""),
    re.compile(r"from\s+['\"](?:crypto|node:crypto|bcrypt|argon2|jsonwebtoken|jose|tweetnacl|crypto-js)['\"]"),
]

_GO_CRYPTO_PATTERNS = [
    re.compile(r'"crypto/(?:aes|cipher|des|dsa|ecdsa|ed25519|hmac|md5|rand|rsa|sha256|sha512|tls|x509)"'),
    re.compile(r'"golang\.org/x/crypto/(?:argon2|bcrypt|chacha20|nacl|ssh)"'),
]

# ── Hashing function calls to detect ─────────────────────────────────

_HASH_FUNCTIONS = frozenset({
    "sha256", "sha384", "sha512", "sha1", "md5",
    "pbkdf2_hmac", "scrypt", "blake2b", "blake2s",
    "new",  # hashlib.new("sha256", ...)
})

_PASSWORD_HASH_CALLS = frozenset({
    "bcrypt.hashpw", "bcrypt.gensalt", "bcrypt.checkpw",
    "argon2.hash", "argon2.verify",
    "passlib.hash",
    "pbkdf2_hmac",
})

# ── Hardcoded secret patterns ────────────────────────────────────────

_SECRET_PATTERNS = [
    # JWT secrets
    (re.compile(
        r"""(?:JWT_SECRET|SECRET_KEY|JWT_KEY|TOKEN_SECRET|SIGNING_KEY)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{16,})['"]""",
        re.IGNORECASE,
    ), "jwt_secret"),
    # API keys
    (re.compile(
        r"""(?:API_KEY|APIKEY|api_key)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]""",
        re.IGNORECASE,
    ), "api_key"),
    # Static IVs (hex)
    (re.compile(
        r"""(?:iv|IV|initialization_vector|nonce)\s*[:=]\s*(?:b['"]|bytes\.fromhex\s*\(\s*['"])([0-9a-fA-F]{16,})""",
        re.IGNORECASE,
    ), "static_iv"),
    # Private keys embedded in source
    (re.compile(
        r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
    ), "private_key"),
    # AWS-style keys
    (re.compile(
        r"""(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""",
    ), "aws_access_key"),
]

# ── File extensions to scan ──────────────────────────────────────────

_PYTHON_EXTS = frozenset({".py"})
_JAVA_EXTS = frozenset({".java", ".kt", ".scala"})
_JS_EXTS = frozenset({".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"})
_GO_EXTS = frozenset({".go"})

_SKIP_DIRS = frozenset({
    "__pycache__", "node_modules", ".git", ".venv", "venv",
    "env", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", "site-packages",
})

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB cap


class SASTCryptoEngine(ScanStage):
    """Track B — Stage 13: Static Code Analysis for cryptographic usage."""

    name = "sast_crypto"
    order = 20
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields: list[str] = []
    writes_fields = ["sast_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        source_paths: list[str] = []

        # Accept paths from scan options
        raw = ctx.options.get("source_code_paths") or ctx.options.get("source_code_path")
        if isinstance(raw, str):
            source_paths = [raw]
        elif isinstance(raw, list):
            source_paths = [str(p) for p in raw]

        if not source_paths:
            logger.info("[%s] SAST: no source_code_paths configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={"sast_findings": []},
                error="No source_code_paths provided in scan options",
            )

        all_findings: list[dict] = []

        for base_path in source_paths:
            if not os.path.isdir(base_path):
                logger.warning("[%s] SAST: path %s is not a directory", ctx.scan_id, base_path)
                continue
            all_findings.extend(self._scan_directory(base_path))

        logger.info(
            "[%s] SAST: completed — %d findings across %d path(s)",
            ctx.scan_id, len(all_findings), len(source_paths),
        )

        return StageResult(
            status="completed",
            data={"sast_findings": all_findings},
        )

    # ── directory walker ─────────────────────────────────────────────

    def _scan_directory(self, base_path: str) -> list[dict]:
        findings: list[dict] = []

        for root, dirs, files in os.walk(base_path, topdown=True):
            # Prune skippable directories in-place
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

            for filename in files:
                filepath = os.path.join(root, filename)
                _, ext = os.path.splitext(filename)
                ext = ext.lower()

                # Size guard
                try:
                    if os.path.getsize(filepath) > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                        source = fh.read()
                except (OSError, UnicodeDecodeError):
                    continue

                if ext in _PYTHON_EXTS:
                    findings.extend(self._analyze_python(filepath, source))
                elif ext in _JAVA_EXTS:
                    findings.extend(self._analyze_java(filepath, source))
                elif ext in _JS_EXTS:
                    findings.extend(self._analyze_js(filepath, source))
                elif ext in _GO_EXTS:
                    findings.extend(self._analyze_go(filepath, source))

                # Hardcoded secrets scan (all languages)
                findings.extend(self._scan_hardcoded_secrets(filepath, source))

        return findings

    # ── Python AST analysis ──────────────────────────────────────────

    def _analyze_python(self, filepath: str, source: str) -> list[dict]:
        findings: list[dict] = []

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # 1. Import detection
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base = alias.name.split(".")[0]
                    if base in _PYTHON_CRYPTO_MODULES:
                        findings.append(SASTFinding(
                            file_path=filepath,
                            line_number=node.lineno,
                            finding_type="import",
                            module=alias.name,
                            evidence=f"import {alias.name}",
                            severity="info",
                            confidence=0.95,
                        ).model_dump())

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base = node.module.split(".")[0]
                    if base in _PYTHON_CRYPTO_MODULES:
                        imported = ", ".join(a.name for a in node.names)
                        findings.append(SASTFinding(
                            file_path=filepath,
                            line_number=node.lineno,
                            finding_type="import",
                            module=f"{node.module}.{node.names[0].name}",
                            evidence=f"from {node.module} import {imported}",
                            severity="info",
                            confidence=0.95,
                        ).model_dump())

            # 2. Function call detection (hashlib.sha256, bcrypt.hashpw, etc.)
            elif isinstance(node, ast.Call):
                func_name = self._extract_call_name(node)
                if not func_name:
                    continue

                # Direct hash function calls
                parts = func_name.split(".")
                if parts[-1] in _HASH_FUNCTIONS:
                    algo = parts[-1]
                    # Special case: hashlib.new("sha256") → extract algo from args
                    if algo == "new" and node.args:
                        if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            algo = node.args[0].value

                    findings.append(SASTFinding(
                        file_path=filepath,
                        line_number=node.lineno,
                        finding_type="function_call",
                        module=".".join(parts[:-1]) if len(parts) > 1 else None,
                        algorithm=algo,
                        evidence=f"Call to {func_name}()",
                        severity="medium",
                        confidence=0.90,
                    ).model_dump())

                # Password hashing calls
                if func_name in _PASSWORD_HASH_CALLS or any(
                    func_name.endswith(ph.split(".")[-1]) for ph in _PASSWORD_HASH_CALLS
                ):
                    findings.append(SASTFinding(
                        file_path=filepath,
                        line_number=node.lineno,
                        finding_type="function_call",
                        module=".".join(parts[:-1]) if len(parts) > 1 else None,
                        algorithm=parts[-1],
                        evidence=f"Password hashing: {func_name}()",
                        severity="info",
                        confidence=0.90,
                    ).model_dump())

                # Fernet / AES construction
                if "Fernet" in func_name or "AESGCM" in func_name or "ChaCha20" in func_name:
                    findings.append(SASTFinding(
                        file_path=filepath,
                        line_number=node.lineno,
                        finding_type="function_call",
                        algorithm=parts[-1],
                        evidence=f"Symmetric encryption: {func_name}()",
                        severity="info",
                        confidence=0.90,
                    ).model_dump())

        return findings

    @staticmethod
    def _extract_call_name(node: ast.Call) -> str | None:
        """Recursively extract the dotted name from a Call node."""
        func = node.func
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        elif isinstance(func, ast.Attribute):
            parts.append(func.attr)
        if not parts:
            return None
        parts.reverse()
        return ".".join(parts)

    # ── Java regex analysis ──────────────────────────────────────────

    def _analyze_java(self, filepath: str, source: str) -> list[dict]:
        findings: list[dict] = []
        for pattern in _JAVA_CRYPTO_PATTERNS:
            for m in pattern.finditer(source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(SASTFinding(
                    file_path=filepath,
                    line_number=line_num,
                    finding_type="import",
                    module=m.group(1),
                    evidence=m.group(0).strip(),
                    severity="info",
                    confidence=0.90,
                ).model_dump())

        # Detect getInstance("AES/GCM/...") patterns
        cipher_pattern = re.compile(
            r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)', re.MULTILINE
        )
        for m in cipher_pattern.finditer(source):
            line_num = source[:m.start()].count("\n") + 1
            algo_str = m.group(1)
            algo_parts = algo_str.split("/")
            findings.append(SASTFinding(
                file_path=filepath,
                line_number=line_num,
                finding_type="function_call",
                algorithm=algo_parts[0] if algo_parts else algo_str,
                evidence=f"Cipher.getInstance(\"{algo_str}\")",
                severity="medium",
                confidence=0.90,
            ).model_dump())

        return findings

    # ── JavaScript / TypeScript regex analysis ───────────────────────

    def _analyze_js(self, filepath: str, source: str) -> list[dict]:
        findings: list[dict] = []
        for pattern in _JS_CRYPTO_PATTERNS:
            for m in pattern.finditer(source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(SASTFinding(
                    file_path=filepath,
                    line_number=line_num,
                    finding_type="import",
                    module=m.group(0).strip(),
                    evidence=m.group(0).strip(),
                    severity="info",
                    confidence=0.85,
                ).model_dump())

        # crypto.createHash / createCipher / createSign patterns
        node_crypto = re.compile(
            r"(?:crypto|createHash|createCipheriv|createSign|createHmac)\s*\(\s*['\"]([a-zA-Z0-9\-]+)['\"]",
        )
        for m in node_crypto.finditer(source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(SASTFinding(
                file_path=filepath,
                line_number=line_num,
                finding_type="function_call",
                algorithm=m.group(1),
                evidence=m.group(0).strip(),
                severity="medium",
                confidence=0.85,
            ).model_dump())

        return findings

    # ── Go regex analysis ────────────────────────────────────────────

    def _analyze_go(self, filepath: str, source: str) -> list[dict]:
        findings: list[dict] = []
        for pattern in _GO_CRYPTO_PATTERNS:
            for m in pattern.finditer(source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(SASTFinding(
                    file_path=filepath,
                    line_number=line_num,
                    finding_type="import",
                    module=m.group(0).strip().strip('"'),
                    evidence=m.group(0).strip(),
                    severity="info",
                    confidence=0.85,
                ).model_dump())
        return findings

    # ── Hardcoded secrets scanner ────────────────────────────────────

    def _scan_hardcoded_secrets(self, filepath: str, source: str) -> list[dict]:
        findings: list[dict] = []
        for pattern, secret_type in _SECRET_PATTERNS:
            for m in pattern.finditer(source):
                line_num = source[:m.start()].count("\n") + 1
                evidence = m.group(0)[:80]  # Truncate to avoid leaking full secrets
                findings.append(SASTFinding(
                    file_path=filepath,
                    line_number=line_num,
                    finding_type="hardcoded_secret",
                    secret_type=secret_type,
                    evidence=f"Hardcoded {secret_type}: {evidence}…",
                    severity="critical" if secret_type == "private_key" else "high",
                    confidence=0.75,
                ).model_dump())
        return findings
