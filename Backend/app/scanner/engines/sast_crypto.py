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

from app.scanner.acquisition.repository_intake import SourceAcquisitionManager
from app.scanner.discovery.source_files import SourceDiscoveryManager, SourceFile
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
        repo_urls: list[str] = []
        
        # Accept paths and urls from scan options
        raw_paths = ctx.options.get("source_code_paths") or ctx.options.get("source_code_path")
        if isinstance(raw_paths, str):
            source_paths = [raw_paths]
        elif isinstance(raw_paths, list):
            source_paths = [str(p) for p in raw_paths]
            
        raw_urls = ctx.options.get("repository_urls")
        if isinstance(raw_urls, str):
            repo_urls = [raw_urls]
        elif isinstance(raw_urls, list):
            repo_urls = [str(u) for u in raw_urls]

        if not source_paths and not repo_urls:
            logger.info("[%s] SAST: no source inputs configured — skipping", ctx.scan_id)
            return StageResult(
                status="skipped",
                data={"sast_findings": []},
                error="No source_code_paths or repository_urls provided",
            )

        all_findings: list[dict] = []
        acquisition = SourceAcquisitionManager()
        discovery = SourceDiscoveryManager()
        acquired_sources = []
        
        try:
            # Acquire Local Paths
            for local_path in source_paths:
                try:
                    src = await acquisition.acquire(ctx.scan_id, local_path=local_path)
                    acquired_sources.append(src)
                except Exception as e:
                    logger.warning("[%s] SAST: Failed to acquire local %s: %s", ctx.scan_id, local_path, e)

            # Acquire GitHub URLs
            for url in repo_urls:
                try:
                    src = await acquisition.acquire(ctx.scan_id, github_url=url)
                    acquired_sources.append(src)
                except Exception as e:
                    logger.warning("[%s] SAST: Failed to acquire URL %s: %s", ctx.scan_id, url, e)

            # Discover and Scan
            for src in acquired_sources:
                logger.info("[%s] SAST: Discovering files in %s (scope: %s)", ctx.scan_id, src.local_root, src.selected_scope)
                try:
                    source_files, skipped = discovery.discover(src.local_root, src.selected_scope)
                    
                    for sf in source_files:
                        findings = self._analyze_file(sf)
                        # Decorate with acquisition context
                        for f in findings:
                            f["repository"] = src.repository
                            f["commit"] = src.commit_sha
                            f["branch"] = src.branch
                            f["scope"] = src.selected_scope
                            all_findings.append(f)
                except Exception as e:
                    logger.error("[%s] SAST: Error scanning source %s: %s", ctx.scan_id, src.original_url, e)

        finally:
            acquisition.cleanup(ctx.scan_id)

        logger.info(
            "[%s] SAST: completed — %d findings across %d source(s)",
            ctx.scan_id, len(all_findings), len(acquired_sources),
        )

        return StageResult(
            status="completed",
            data={"sast_findings": all_findings},
        )

    def _analyze_file(self, sf: SourceFile) -> list[dict]:
        findings: list[dict] = []
        
        try:
            with open(sf.file_path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except (OSError, UnicodeDecodeError):
            return findings

        if sf.language == "python":
            from app.scanner.engines.python_analyzer import PythonASTAnalyzer
            analyzer = PythonASTAnalyzer()
            findings.extend(analyzer.analyze(sf, source))
            
            from app.scanner.engines.syntax_regex_analyzer import SyntaxRegexAnalyzer
            sra = SyntaxRegexAnalyzer()
            findings.extend(sra.scan_hardcoded_secrets(sf, source))
        else:
            from app.scanner.engines.syntax_regex_analyzer import SyntaxRegexAnalyzer
            sra = SyntaxRegexAnalyzer()
            
            if sf.language == "java":
                findings.extend(sra.analyze_java(sf, source))
            elif sf.language in ("javascript", "typescript"):
                findings.extend(sra.analyze_js(sf, source))
            elif sf.language == "go":
                findings.extend(sra.analyze_go(sf, source))
                
            findings.extend(sra.scan_hardcoded_secrets(sf, source))

        return findings


