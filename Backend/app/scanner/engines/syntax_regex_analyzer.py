"""
QuantumShield — Syntax-Aware Regex Analyzer
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

from app.scanner.models import SASTFinding
from app.scanner.discovery.source_files import SourceFile

_JAVA_CRYPTO_PATTERNS = [
    (re.compile(r"import\s+(javax\.crypto\.[A-Za-z.]+)", re.MULTILINE), "import", None),
    (re.compile(r"import\s+(java\.security\.[A-Za-z.]+)", re.MULTILINE), "import", None),
    (re.compile(r"import\s+(org\.bouncycastle\.[A-Za-z.]+)", re.MULTILINE), "import", None),
]

_JS_CRYPTO_PATTERNS = [
    (re.compile(r"""(?:require|import)\s*\(?\s*['"](?:crypto|node:crypto|bcrypt|argon2|jsonwebtoken|jose|tweetnacl|crypto-js)['"]"""), "import", None),
    (re.compile(r"from\s+['\"](?:crypto|node:crypto|bcrypt|argon2|jsonwebtoken|jose|tweetnacl|crypto-js)['\"]"), "import", None),
]

_GO_CRYPTO_PATTERNS = [
    (re.compile(r'"crypto/(?:aes|cipher|des|dsa|ecdsa|ed25519|hmac|md5|rand|rsa|sha256|sha512|tls|x509)"'), "import", None),
    (re.compile(r'"golang\.org/x/crypto/(?:argon2|bcrypt|chacha20|nacl|ssh)"'), "import", None),
]

_SECRET_PATTERNS = [
    (re.compile(r"""(?:JWT_SECRET|SECRET_KEY|JWT_KEY|TOKEN_SECRET|SIGNING_KEY)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{16,})['"]""", re.IGNORECASE), "jwt_secret"),
    (re.compile(r"""(?:API_KEY|APIKEY|api_key)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]""", re.IGNORECASE), "api_key"),
    (re.compile(r"""(?:iv|IV|initialization_vector|nonce)\s*[:=]\s*(?:b['"]|bytes\.fromhex\s*\(\s*['"])([0-9a-fA-F]{16,})""", re.IGNORECASE), "static_iv"),
    (re.compile(r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----"), "private_key"),
    (re.compile(r"""(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"""), "aws_access_key"),
]


class SyntaxRegexAnalyzer:
    """
    Syntax-aware Regex Analyzer that strips comments and string literals
    before looking for cryptographic APIs, to avoid false positives.
    """
    
    def __init__(self):
        pass

    def _strip_comments_and_strings(self, source: str, language: str) -> str:
        """Replace comments and strings with whitespace to preserve line numbers."""
        def replacer(match):
            return " " * len(match.group(0))

        if language in ("java", "javascript", "typescript", "go"):
            # Block comments /* ... */
            source = re.sub(r'/\*.*?\*/', replacer, source, flags=re.DOTALL)
            # Line comments // ...
            source = re.sub(r'//.*', replacer, source)
            # Strings "..." and '...'
            source = re.sub(r'"(?:\\.|[^"\\])*"', replacer, source)
            source = re.sub(r"'(?:\\.|[^'\\])*'", replacer, source)
            
            if language in ("javascript", "typescript"):
                # Template literals `...`
                source = re.sub(r'`(?:\\.|[^`\\])*`', replacer, source, flags=re.DOTALL)

        elif language == "python":
            # Strings and docstrings
            source = re.sub(r'"""(?:\\.|[^"\\])*"""', replacer, source, flags=re.DOTALL)
            source = re.sub(r"'''(?:\\.|[^'\\])*'''", replacer, source, flags=re.DOTALL)
            source = re.sub(r'"(?:\\.|[^"\\])*"', replacer, source)
            source = re.sub(r"'(?:\\.|[^'\\])*'", replacer, source)
            # Line comments # ...
            source = re.sub(r'#.*', replacer, source)
            
        return source

    def analyze_java(self, sf: SourceFile, source: str) -> list[dict]:
        findings = []
        clean_source = self._strip_comments_and_strings(source, "java")
        now = datetime.now(timezone.utc).isoformat()
        
        for pattern, ftype, module in _JAVA_CRYPTO_PATTERNS:
            for m in pattern.finditer(clean_source):
                line_num = clean_source[:m.start()].count("\n") + 1
                matched_module = m.group(1) if len(m.groups()) > 0 else module
                evidence = source[m.start():m.end()].strip()
                
                f = SASTFinding(
                    file_path=sf.file_path,
                    language=sf.language,
                    line_number=line_num,
                    finding_type=ftype,
                    evidence_type="REGEX",
                    module=matched_module,
                    evidence=evidence,
                    severity="info",
                    confidence=0.90,
                    observed_at=now
                )
                findings.append(f.model_dump())

        # Detect Cipher.getInstance("AES/GCM/NoPadding")
        cipher_pattern = re.compile(r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)', re.MULTILINE)
        # Note: We match against the original source here because we *need* the string literal content
        # But we verify the call itself isn't commented out by checking clean_source.
        for m in cipher_pattern.finditer(source):
            start = m.start()
            if clean_source[start:start+6] != "Cipher":
                continue # It was in a comment
                
            line_num = source[:m.start()].count("\n") + 1
            algo_str = m.group(1)
            parts = algo_str.split("/")
            
            f = SASTFinding(
                file_path=sf.file_path,
                language=sf.language,
                line_number=line_num,
                finding_type="function_call",
                evidence_type="REGEX",
                api="Cipher",
                operation="ENCRYPT",
                algorithm=parts[0].upper() if len(parts) > 0 else None,
                mode=parts[1].upper() if len(parts) > 1 else None,
                padding=parts[2] if len(parts) > 2 else None,
                evidence=f'Cipher.getInstance("{algo_str}")',
                severity="info",
                confidence=0.90,
                observed_at=now
            )
            findings.append(f.model_dump())

        return findings

    def analyze_js(self, sf: SourceFile, source: str) -> list[dict]:
        findings = []
        clean_source = self._strip_comments_and_strings(source, sf.language)
        now = datetime.now(timezone.utc).isoformat()
        
        for pattern, ftype, _ in _JS_CRYPTO_PATTERNS:
            for m in pattern.finditer(clean_source):
                line_num = clean_source[:m.start()].count("\n") + 1
                evidence = source[m.start():m.end()].strip()
                
                f = SASTFinding(
                    file_path=sf.file_path,
                    language=sf.language,
                    line_number=line_num,
                    finding_type=ftype,
                    evidence_type="REGEX",
                    evidence=evidence,
                    severity="info",
                    confidence=0.85,
                    observed_at=now
                )
                findings.append(f.model_dump())

        # crypto.createHash / createCipher
        node_crypto = re.compile(r"(?:crypto|createHash|createCipheriv|createSign|createHmac)\s*\(\s*['\"]([a-zA-Z0-9\-]+)['\"]")
        for m in node_crypto.finditer(source):
            start = m.start()
            if not clean_source[start:start+2].isalpha():
                continue
                
            line_num = source[:m.start()].count("\n") + 1
            algo = m.group(1)
            evidence = source[m.start():m.end()].strip()
            
            f = SASTFinding(
                file_path=sf.file_path,
                language=sf.language,
                line_number=line_num,
                finding_type="function_call",
                evidence_type="REGEX",
                algorithm=algo.upper(),
                evidence=evidence,
                severity="info",
                confidence=0.85,
                observed_at=now
            )
            findings.append(f.model_dump())

        return findings

    def analyze_go(self, sf: SourceFile, source: str) -> list[dict]:
        findings = []
        clean_source = self._strip_comments_and_strings(source, "go")
        now = datetime.now(timezone.utc).isoformat()
        
        for pattern, ftype, _ in _GO_CRYPTO_PATTERNS:
            for m in pattern.finditer(clean_source):
                line_num = clean_source[:m.start()].count("\n") + 1
                
                # Extract the actual import string
                match_str = m.group(0).strip().strip('"')
                
                f = SASTFinding(
                    file_path=sf.file_path,
                    language=sf.language,
                    line_number=line_num,
                    finding_type=ftype,
                    evidence_type="REGEX",
                    module=match_str,
                    evidence=source[m.start():m.end()].strip(),
                    severity="info",
                    confidence=0.85,
                    observed_at=now
                )
                findings.append(f.model_dump())
        return findings

    def scan_hardcoded_secrets(self, sf: SourceFile, source: str) -> list[dict]:
        findings = []
        clean_source = self._strip_comments_and_strings(source, sf.language)
        now = datetime.now(timezone.utc).isoformat()
        
        for pattern, secret_type in _SECRET_PATTERNS:
            for m in pattern.finditer(source):
                # Only warn if the secret isn't commented out
                start = m.start()
                if clean_source[start:start+1] == " ":
                    continue # Inside comment
                    
                line_num = source[:m.start()].count("\n") + 1
                raw_secret = m.group(1) if len(m.groups()) > 0 else m.group(0)
                fingerprint = f"sha256:{hashlib.sha256(raw_secret.encode('utf-8')).hexdigest()}"
                
                f = SASTFinding(
                    file_path=sf.file_path,
                    language=sf.language,
                    line_number=line_num,
                    finding_type="HARDCODED_SECRET",
                    evidence_type="REGEX",
                    secret_type=secret_type,
                    evidence="[REDACTED]",
                    fingerprint=fingerprint,
                    severity="info", # Neutral observation
                    confidence=0.75,
                    observed_at=now
                )
                findings.append(f.model_dump())
        return findings
