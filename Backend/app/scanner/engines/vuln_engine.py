"""
QuantumShield — Vulnerability Engine (Stage 10)

Rule-based vulnerability detection + CVE correlation.  Replaces the
external Nuclei subprocess and the static 8-lambda cve_mapper.py with
a JSON-driven rule engine and behavioural misconfig probes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from app.scanner.models import StageResult, VulnFinding
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

BUILTIN_RULES: list[dict] = [
    {
        "id": "QS-VULN-TLS-001", "name": "TLS 1.0 Enabled", "severity": "high",
        "category": "tls_misconfig",
        "check": lambda ctx: [
            {"host": p.get("host"), "port": p.get("port"),
             "evidence": f"Host {p.get('host')}:{p.get('port')} accepts TLS 1.0"}
            for p in (ctx.tls_profiles or [])
            if (p if isinstance(p, dict) else {}).get("tls_versions_supported", {}).get("TLS_1_0")
        ],
        "remediation": "Disable TLS 1.0. Require TLS 1.2 minimum.",
        "cve_ids": ["CVE-2011-3389", "CVE-2014-3566"],
        "quantum_relevance": True,
    },
    {
        "id": "QS-VULN-TLS-002", "name": "TLS 1.1 Enabled", "severity": "medium",
        "category": "tls_misconfig",
        "check": lambda ctx: [
            {"host": p.get("host"), "port": p.get("port"),
             "evidence": f"Host {p.get('host')}:{p.get('port')} accepts TLS 1.1"}
            for p in (ctx.tls_profiles or [])
            if (p if isinstance(p, dict) else {}).get("tls_versions_supported", {}).get("TLS_1_1")
        ],
        "remediation": "Disable TLS 1.1. Require TLS 1.2 minimum.",
        "cve_ids": [],
        "quantum_relevance": True,
    },
    {
        "id": "QS-VULN-CERT-001", "name": "Expired Certificate", "severity": "critical",
        "category": "tls_misconfig",
        "check": lambda ctx: [
            {"host": p.get("host"), "port": p.get("port"),
             "evidence": f"Certificate on {p.get('host')} expired"}
            for p in (ctx.tls_profiles or [])
            if (p if isinstance(p, dict) else {}).get("leaf_cert", {}).get("expired")
        ],
        "remediation": "Renew the TLS certificate immediately.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-CERT-002", "name": "Self-Signed Certificate", "severity": "high",
        "category": "tls_misconfig",
        "check": lambda ctx: [
            {"host": p.get("host"), "port": p.get("port"),
             "evidence": f"Self-signed certificate on {p.get('host')}"}
            for p in (ctx.tls_profiles or [])
            if (p if isinstance(p, dict) else {}).get("leaf_cert", {}).get("is_self_signed")
        ],
        "remediation": "Replace with a certificate from a trusted CA.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-HDR-001", "name": "Missing HSTS Header", "severity": "medium",
        "category": "missing_header",
        "check": lambda ctx: [
            {"host": w.get("host"),
             "evidence": f"Host {w.get('host')} missing Strict-Transport-Security"}
            for w in (ctx.web_profiles or [])
            if not (w if isinstance(w, dict) else {}).get("security_headers", {}).get("strict-transport-security", {}).get("present")
        ],
        "remediation": "Add Strict-Transport-Security header with max-age >= 31536000.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-HDR-002", "name": "Missing CSP Header", "severity": "medium",
        "category": "missing_header",
        "check": lambda ctx: [
            {"host": w.get("host"),
             "evidence": f"Host {w.get('host')} missing Content-Security-Policy"}
            for w in (ctx.web_profiles or [])
            if not (w if isinstance(w, dict) else {}).get("security_headers", {}).get("content-security-policy", {}).get("present")
        ],
        "remediation": "Implement a Content-Security-Policy header.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-CORS-001", "name": "Permissive CORS Policy", "severity": "high",
        "category": "misconfig",
        "check": lambda ctx: [
            {"host": w.get("host"),
             "evidence": f"Host {w.get('host')} has permissive CORS (reflects origin or wildcard with credentials)"}
            for w in (ctx.web_profiles or [])
            if (w if isinstance(w, dict) else {}).get("cors", {}).get("is_permissive") and
               (w if isinstance(w, dict) else {}).get("cors", {}).get("credentials_allowed")
        ],
        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted origins.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-EXPOSED-001", "name": "Exposed Database Port", "severity": "critical",
        "category": "network_exposure",
        "check": lambda ctx: [
            {"host": s.get("host"), "port": s.get("port"),
             "evidence": f"Database service {s.get('service_name')} exposed on {s.get('host')}:{s.get('port')}"}
            for s in (ctx.services or [])
            if (s if isinstance(s, dict) else {}).get("protocol_category") == "db" and
               (s if isinstance(s, dict) else {}).get("state") == "open"
        ],
        "remediation": "Restrict database ports to internal networks only.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-HIDDEN-001", "name": "Git Repository Exposed", "severity": "critical",
        "category": "info_disclosure",
        "check": lambda ctx: [
            {"host": h.get("host"), "evidence": h.get("evidence", "")}
            for h in (ctx.hidden_findings or [])
            if (h if isinstance(h, dict) else {}).get("finding_type") == "git_exposure" and
               (h if isinstance(h, dict) else {}).get("confidence", 0) >= 0.8
        ],
        "remediation": "Block access to .git directory via web server configuration.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
    {
        "id": "QS-VULN-HIDDEN-002", "name": "Environment File Exposed", "severity": "critical",
        "category": "info_disclosure",
        "check": lambda ctx: [
            {"host": h.get("host"), "evidence": h.get("evidence", "")}
            for h in (ctx.hidden_findings or [])
            if (h if isinstance(h, dict) else {}).get("finding_type") == "config_exposure" and
               ".env" in (h if isinstance(h, dict) else {}).get("path", "") and
               (h if isinstance(h, dict) else {}).get("confidence", 0) >= 0.8
        ],
        "remediation": "Remove .env files from the web root and block access.",
        "cve_ids": [],
        "quantum_relevance": False,
    },
]


class VulnerabilityEngine(ScanStage):
    name = "vuln_engine"
    order = 10
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields: list[str] = []
    writes_fields = ["vuln_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        findings: list[dict] = []
        seen: set[str] = set()

        for rule in BUILTIN_RULES:
            try:
                matches = rule["check"](ctx)
                for m in (matches or []):
                    host = m.get("host", "")
                    key = f"{host}|{rule['id']}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(VulnFinding(
                        host=host,
                        vuln_id=rule["id"],
                        name=rule["name"],
                        severity=rule["severity"],
                        category=rule["category"],
                        evidence=m.get("evidence", ""),
                        confidence=0.85,
                        remediation=rule["remediation"],
                        cve_ids=rule.get("cve_ids", []),
                        affected_component=m.get("port"),
                        quantum_relevance=rule.get("quantum_relevance", False),
                    ).model_dump())
            except Exception:
                logger.debug("Rule %s failed", rule.get("id"), exc_info=True)

        cve_findings = self._correlate_cves(ctx)
        findings.extend(cve_findings)

        return StageResult(
            status="completed",
            data={"vuln_findings": findings},
        )

    def _correlate_cves(self, ctx: ScanContext) -> list[dict]:
        cve_cache = self._load_cve_cache()
        if not cve_cache:
            return []

        findings: list[dict] = []
        seen: set[str] = set()

        for tech in (ctx.tech_fingerprints or []):
            t = tech if isinstance(tech, dict) else {}
            cpe = t.get("cpe") or ""
            version = t.get("version") or ""
            host = t.get("host", "")
            if not cpe or not version:
                continue

            for cve_entry in cve_cache:
                if cpe.startswith(cve_entry.get("cpe_prefix", "___")):
                    affected = cve_entry.get("affected_versions", [])
                    if version in affected or "*" in affected:
                        key = f"{host}|{cve_entry['cve_id']}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(VulnFinding(
                            host=host,
                            vuln_id=cve_entry["cve_id"],
                            name=cve_entry.get("name", cve_entry["cve_id"]),
                            severity=cve_entry.get("severity", "high"),
                            category="cve",
                            evidence=f"{t.get('name')} {version} matches {cve_entry['cve_id']}",
                            confidence=0.75,
                            remediation=cve_entry.get("remediation", "Update to the latest version."),
                            cve_ids=[cve_entry["cve_id"]],
                            affected_component=t.get("name"),
                            quantum_relevance=False,
                        ).model_dump())

        return findings

    @staticmethod
    def _load_cve_cache() -> list[dict]:
        path = _DATA_DIR / "cve_cache.json"
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return []
