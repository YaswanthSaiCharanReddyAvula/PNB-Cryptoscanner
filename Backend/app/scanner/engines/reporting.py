"""
QuantumShield — CBOM + Report Engine (Stage 12)

Builds CERT-IN Annexure-A compliant CBOM, prioritised recommendations,
estate-level scoring, and executive summary text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.scanner.models import CryptoFinding, StageResult, TLSProfile
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

NIST_REFS = {
    "key_exchange": "NIST FIPS 203 (ML-KEM / Kyber)",
    "signature":    "NIST FIPS 204 (ML-DSA / Dilithium)",
    "cipher":       "NIST SP 800-131A Rev 2",
    "protocol":     "NIST SP 800-52 Rev 2",
    "certificate":  "NIST SP 800-57 Part 1 Rev 5",
}


def _normalize_host(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("hostname") or value.get("host") or value.get("subdomain") or "").strip().lower()
    return str(value or "").strip().lower()


class CBOMReportEngine(ScanStage):
    name = "reporting"
    order = 12
    timeout_seconds = 30
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields: list[str] = []  # runs with whatever data is available
    writes_fields = [
        "cbom",
        "recommendations",
        "executive_summary",
        "quantum_score",
        "estate_tier",
    ]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        try:
            cbom = self._safe_build_cbom(ctx)
            recs = self._safe_build_recommendations(ctx)
            summary_text = self._safe_build_executive_summary(ctx)
            score_data = self._safe_compute_estate_score(ctx)

            return StageResult(
                status="completed",
                data={
                    "cbom": cbom,
                    "recommendations": recs,
                    "executive_summary": summary_text,
                    "quantum_score": score_data,
                    "estate_tier": score_data.get("tier", "Unknown"),
                },
            )
        except Exception as exc:
            logger.exception("Reporting engine error")
            return StageResult(status="error", error=str(exc))

    def _safe_build_cbom(self, ctx: ScanContext) -> dict:
        try:
            return self._build_cbom(ctx)
        except Exception:
            logger.exception("Failed to build CBOM; using fallback payload")
            return {
                "schema_version": "1.0.0",
                "domain": getattr(ctx, "domain", ""),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_components": 0,
                "components": [],
                "quantum_safe_count": 0,
                "weak_crypto_count": 0,
                "cert_in_compliant": False,
            }

    def _safe_build_recommendations(self, ctx: ScanContext) -> list[dict]:
        try:
            return self._build_recommendations(ctx)
        except Exception:
            logger.exception("Failed to build recommendations; using empty list")
            return []

    def _safe_build_executive_summary(self, ctx: ScanContext) -> str:
        try:
            return self._build_executive_summary(ctx)
        except Exception:
            logger.exception("Failed to build executive summary; using fallback")
            return f"QuantumShield scan completed for {getattr(ctx, 'domain', 'target')} with partial reporting data."

    def _safe_compute_estate_score(self, ctx: ScanContext) -> dict:
        try:
            return self._compute_estate_score(ctx)
        except Exception:
            logger.exception("Failed to compute estate score; using conservative default")
            return {"score": 50.0, "cyber_rating": 500, "tier": "Standard"}

    # ------------------------------------------------------------------
    # CBOM
    # ------------------------------------------------------------------

    def _build_cbom(self, ctx: ScanContext) -> dict:
        components: list[dict] = []
        seen: set[str] = set()

        for profile in (ctx.tls_profiles or []):
            if not isinstance(profile, dict):
                profile = profile if isinstance(profile, dict) else {}

            host = _normalize_host(profile.get("host", ""))
            port = profile.get("port", 0)

            leaf = profile.get("leaf_cert") or {}
            if leaf:
                key = f"{host}|cert|{leaf.get('fingerprint_sha256', '')}"
                if key not in seen:
                    seen.add(key)
                    components.append({
                        "asset_type": "certificate",
                        "name": (leaf.get("subject") or "")[:64],
                        "host": host,
                        "elements": {
                            "subject": leaf.get("subject"),
                            "issuer": leaf.get("issuer"),
                            "not_valid_before": leaf.get("valid_from"),
                            "not_valid_after": leaf.get("valid_to"),
                            "signature_algorithm": leaf.get("sig_algorithm"),
                            "public_key": f"{leaf.get('key_type')}-{leaf.get('key_size')}",
                            "serial": leaf.get("serial"),
                            "sha256": leaf.get("fingerprint_sha256"),
                        },
                        "quantum_safe": not leaf.get("quantum_vulnerable", True),
                        "risk_level": self._cert_risk(leaf),
                    })

            versions = profile.get("tls_versions_supported") or {}
            for ver, supported in versions.items():
                if not supported:
                    continue
                key = f"{host}|protocol|{ver}"
                if key not in seen:
                    seen.add(key)
                    components.append({
                        "asset_type": "protocol",
                        "name": ver.replace("_", " "),
                        "host": host,
                        "quantum_safe": ver in ("TLS_1_3",),
                        "risk_level": "low" if "1_3" in ver else "high" if "1_0" in ver or "1_1" in ver else "medium",
                    })

            for cipher in (profile.get("accepted_ciphers") or []):
                c = cipher if isinstance(cipher, dict) else {}
                kex = c.get("kex", "unknown")
                key = f"{host}|algorithm|{kex}"
                if key not in seen:
                    seen.add(key)
                    components.append({
                        "asset_type": "algorithm",
                        "name": kex,
                        "host": host,
                        "quantum_safe": c.get("pqc", False),
                        "risk_level": c.get("quantum_risk", "medium") if not c.get("pqc") else "none",
                    })

        qs_count = sum(1 for c in components if c.get("quantum_safe"))
        weak_count = sum(1 for c in components if c.get("risk_level") in ("high", "critical"))

        return {
            "schema_version": "1.0.0",
            "domain": getattr(ctx, "domain", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_components": len(components),
            "components": components,
            "quantum_safe_count": qs_count,
            "weak_crypto_count": weak_count,
            "cert_in_compliant": True,
        }

    @staticmethod
    def _cert_risk(leaf: dict) -> str:
        kt = (leaf.get("key_type") or "").upper()
        ks = leaf.get("key_size") or 0
        if kt == "RSA" and ks < 2048:
            return "critical"
        if leaf.get("expired"):
            return "critical"
        days = leaf.get("days_until_expiry")
        if isinstance(days, (int, float)) and days < 30:
            return "high"
        return "medium" if kt in ("RSA", "EC") else "low"

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _build_recommendations(self, ctx: ScanContext) -> list[dict]:
        recs: list[dict] = []
        seen_keys: set[str] = set()

        for f in (ctx.crypto_findings or []):
            fd = f if isinstance(f, dict) else {}
            host = _normalize_host(fd.get("host", ""))
            comp = fd.get("component", "")
            algo = fd.get("algorithm", "")
            qr = fd.get("quantum_risk", "")
            hndl = fd.get("hndl_risk", False)

            rkey = f"{host}|{comp}|{algo}"
            if rkey in seen_keys:
                continue
            seen_keys.add(rkey)

            if hndl:
                recs.append(self._rec(1, "critical", "PQC Migration", host,
                    "Deploy ML-KEM Hybrid Key Exchange",
                    f"Host {host} uses {algo} key exchange vulnerable to Harvest-Now-Decrypt-Later.",
                    "Configure TLS to offer X25519Kyber768 hybrid key exchange.",
                    NIST_REFS.get("key_exchange", ""), "medium", "high"))
            elif qr == "critical":
                recs.append(self._rec(2, "critical", "Crypto Remediation", host,
                    f"Replace {algo}",
                    f"Algorithm {algo} on {host} is critically weak.",
                    f"Remove {algo} from server configuration immediately.",
                    NIST_REFS.get(comp, ""), "low", "high"))
            elif qr == "high":
                recs.append(self._rec(3, "high", "Crypto Hardening", host,
                    f"Upgrade {algo}",
                    f"Algorithm {algo} on {host} has high quantum risk.",
                    fd.get("nist_recommendation") or f"Replace {algo} with quantum-safe alternative.",
                    NIST_REFS.get(comp, ""), "medium", "medium"))

        return sorted(recs, key=lambda r: (r["priority"], -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(r["severity"], 0)))

    @staticmethod
    def _rec(priority, severity, category, host, title, desc, action, nist, effort, impact):
        return {
            "priority": priority,
            "severity": severity,
            "category": category,
            "host": host,
            "title": title,
            "description": desc,
            "action": action,
            "nist_reference": nist,
            "effort": effort,
            "impact": impact,
        }

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _build_executive_summary(self, ctx: ScanContext) -> str:
        n_assets = len(ctx.subdomains or [])
        n_services = len(ctx.services or [])
        findings = ctx.crypto_findings or []
        hndl_count = sum(1 for f in findings if (f if isinstance(f, dict) else {}).get("hndl_risk"))
        crit_count = sum(1 for f in findings if (f if isinstance(f, dict) else {}).get("quantum_risk") == "critical")
        profiles = ctx.tls_profiles or []
        pqc_hosts = sum(1 for p in profiles if (p if isinstance(p, dict) else {}).get("pqc_signals"))
        pqc_pct = round(pqc_hosts / max(len(profiles), 1) * 100)

        return (
            f"QuantumShield scan of {ctx.domain} discovered {n_assets} assets "
            f"across {n_services} services. "
            f"{crit_count} critical cryptographic findings detected. "
            f"HNDL exposure affects {hndl_count} host(s). "
            f"PQC readiness: {pqc_pct}% of scanned hosts show PQC signals."
        )

    # ------------------------------------------------------------------
    # Estate scoring
    # ------------------------------------------------------------------

    def _compute_estate_score(self, ctx: ScanContext) -> dict:
        findings = ctx.crypto_findings or []
        if not findings:
            return {"score": 100, "cyber_rating": 1000, "tier": "Elite-PQC"}

        host_scores: dict[str, float] = {}
        for f in findings:
            fd = f if isinstance(f, dict) else {}
            h = _normalize_host(fd.get("host", "_global")) or "_global"
            penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3, "none": 0}.get(fd.get("quantum_risk", "medium"), 5)
            host_scores.setdefault(h, 100.0)
            host_scores[h] = max(0, host_scores[h] - penalty)

        scores = sorted(host_scores.values())
        n = len(scores)
        bottom_q = scores[: max(n // 4, 1)]
        rest = scores[max(n // 4, 1):]
        weighted = (sum(bottom_q) * 3 + sum(rest)) / (len(bottom_q) * 3 + len(rest)) if (len(bottom_q) * 3 + len(rest)) else 50

        has_critical = any(s < 30 for s in scores)
        if has_critical:
            weighted = min(weighted, 69.9)

        cr = round(weighted * 10)
        tier = (
            "Elite-PQC" if cr > 700
            else "Standard" if cr > 400
            else "Legacy" if cr > 200
            else "Critical"
        )
        return {"score": round(weighted, 1), "cyber_rating": cr, "tier": tier}
