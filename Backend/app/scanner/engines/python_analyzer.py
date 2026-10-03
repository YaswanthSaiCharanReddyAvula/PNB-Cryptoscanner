"""
QuantumShield — Python AST Analyzer
"""

import ast
from datetime import datetime, timezone
from typing import Optional

from app.scanner.models import SASTFinding
from app.scanner.discovery.source_files import SourceFile


class PythonASTAnalyzer:
    def __init__(self):
        self.findings = []
        self.aliases = {}
        self.constants = {}
        self.sf = None

    def analyze(self, sf: SourceFile, source: str) -> list[dict]:
        self.findings = []
        self.aliases = {}
        self.constants = {}
        self.sf = sf

        try:
            tree = ast.parse(source, filename=sf.file_path)
        except SyntaxError:
            return self.findings

        self._walk(tree)
        return self.findings

    def _walk(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                asname = alias.asname or name
                self.aliases[asname] = name
                if self._is_crypto_lib(name):
                    self._add_finding(
                        node,
                        finding_type="import",
                        module=name,
                        evidence=f"import {name}" + (f" as {asname}" if alias.asname else ""),
                        confidence=0.95
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module = node.module
                for alias in node.names:
                    name = f"{module}.{alias.name}"
                    asname = alias.asname or alias.name
                    self.aliases[asname] = name
                    if self._is_crypto_lib(module):
                        self._add_finding(
                            node,
                            finding_type="import",
                            module=name,
                            evidence=f"from {module} import {alias.name}" + (f" as {asname}" if alias.asname else ""),
                            confidence=0.95
                        )
        elif isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
                if isinstance(node.value, ast.Constant):
                    self.constants[var_name] = node.value.value
                elif isinstance(node.value, ast.Name) and node.value.id in self.aliases:
                    self.aliases[var_name] = self.aliases[node.value.id]
                elif isinstance(node.value, ast.Attribute):
                    full_name = self._extract_attr(node.value)
                    if full_name:
                        self.aliases[var_name] = self._resolve_alias(full_name)

        elif isinstance(node, ast.Call):
            func_name = self._extract_attr(node.func)
            if func_name:
                resolved_func = self._resolve_alias(func_name)
                
                # Check for algorithms based on API call
                self._check_crypto_call(node, resolved_func)

        for child in ast.iter_child_nodes(node):
            self._walk(child)

    def _is_crypto_lib(self, module: str) -> bool:
        crypto_libs = {
            "hashlib", "hmac", "secrets", "cryptography", "Crypto", "Cryptodome",
            "bcrypt", "argon2", "passlib", "nacl", "pynacl", "jwt", "jose",
            "jwcrypto", "ssl", "OpenSSL", "fernet"
        }
        base = module.split(".")[0]
        return base in crypto_libs

    def _resolve_alias(self, name: str) -> str:
        parts = name.split(".")
        base = parts[0]
        if base in self.aliases:
            parts[0] = self.aliases[base]
        return ".".join(parts)

    def _extract_attr(self, node) -> Optional[str]:
        parts = []
        curr = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        else:
            return None
        parts.reverse()
        return ".".join(parts)

    def _check_crypto_call(self, node: ast.Call, func_name: str):
        # We handle known crypto APIs and extract arguments if they are constants
        parts = func_name.split(".")
        base_mod = parts[0] if len(parts) > 1 else ""
        api = parts[-1]

        finding = None

        if base_mod == "hashlib" or api in {"sha256", "md5", "sha1", "sha512", "sha384"}:
            algo = api
            if api == "new" and node.args and isinstance(node.args[0], ast.Constant):
                algo = str(node.args[0].value)
            elif api == "new" and node.args and isinstance(node.args[0], ast.Name):
                algo = str(self.constants.get(node.args[0].id, "unknown"))
            
            if algo != "new":
                finding = {
                    "operation": "HASH",
                    "algorithm": algo.upper(),
                    "api": api,
                    "module": "hashlib"
                }
                
        elif "Cipher" in api:
            algo = "unknown"
            mode = "unknown"
            # cryptography: Cipher(algorithms.AES(key), modes.CBC(iv))
            if node.args:
                if isinstance(node.args[0], ast.Call):
                    algo = self._extract_attr(node.args[0].func)
                    if algo: algo = algo.split(".")[-1]
                if len(node.args) > 1 and isinstance(node.args[1], ast.Call):
                    mode = self._extract_attr(node.args[1].func)
                    if mode: mode = mode.split(".")[-1]
            
            finding = {
                "operation": "ENCRYPT", # Note: we just assume generic use, operation could be both
                "algorithm": algo.upper() if algo else "unknown",
                "mode": mode.upper() if mode else "unknown",
                "api": "Cipher",
                "module": base_mod
            }
            
        elif api in {"encrypt", "decrypt"}:
            finding = {
                "operation": api.upper(),
                "api": api,
            }

        elif api in {"hashpw", "hash", "checkpw", "verify"} and base_mod in {"bcrypt", "argon2", "passlib"}:
            finding = {
                "operation": "PASSWORD_HASH",
                "algorithm": base_mod.upper(),
                "api": api,
                "module": base_mod
            }

        if finding:
            self._add_finding(
                node,
                finding_type="function_call",
                evidence_type="AST_CALL",
                module=finding.get("module", base_mod),
                api=finding.get("api", api),
                operation=finding.get("operation"),
                algorithm=finding.get("algorithm"),
                mode=finding.get("mode"),
                evidence=f"Call to {func_name}()",
                confidence=0.98
            )

    def _add_finding(self, node, **kwargs):
        now = datetime.now(timezone.utc).isoformat()
        
        f = SASTFinding(
            file_path=self.sf.file_path,
            language=self.sf.language,
            line_number=node.lineno if hasattr(node, 'lineno') else 0,
            column_number=node.col_offset if hasattr(node, 'col_offset') else None,
            observed_at=now,
            severity="info",
            **kwargs
        )
        self.findings.append(f.model_dump())
