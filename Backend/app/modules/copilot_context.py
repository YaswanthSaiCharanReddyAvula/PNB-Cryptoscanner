"""
Compact JSON context for QuantumShield Copilot (no external browsing).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from app.modules.report_bundle import (
    build_export_bundle_payload,
    normalize_host_for_scan_lookup,
)


def _normalize_negotiated_tls_label(raw: Optional[str]) -> str:
    """Bucket negotiated tls_version for distribution (aligned with CBOM charts)."""
    if not raw:
        return "Unknown"
    s = str(raw).strip()
    low = s.lower()
    if "1.3" in low:
        return "TLSv1.3"
    if "1.2" in low:
        return "TLSv1.2"
    if "1.1" in low:
        return "TLSv1.1"
    if "1.0" in low:
        return "TLSv1.0"
    if low in ("tlsv1", "tls1", "tls v1"):
        return "TLSv1.0"
    if "ssl" in low or "sslv2" in low or "sslv3" in low:
        return s[:16] if len(s) > 16 else s
    return s[:20] if len(s) > 20 else s


def _tls_protocol_distribution(tls_results: List[Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for t in tls_results or []:
        if not isinstance(t, dict):
            continue
        if t.get("error"):
            continue
        lab = _normalize_negotiated_tls_label(t.get("tls_version"))
        out[lab] = out.get(lab, 0) + 1
    return out


def _severity_str(v: Any) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return str(v.value)
    return str(v).lower()


def _aggregate_cve_by_severity(cve_list: List[Any]) -> Dict[str, int]:
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0, "unknown": 0}
    for c in cve_list or []:
        if not isinstance(c, dict):
            continue
        sev = _severity_str(c.get("severity"))
        if sev in buckets:
            buckets[sev] += 1
        else:
            buckets["unknown"] += 1
    return {k: v for k, v in buckets.items() if v > 0}


def _aggregate_vuln_by_severity(vuln_list: List[Any]) -> Dict[str, int]:
    buckets: Dict[str, int] = {}
    for v in vuln_list or []:
        if not isinstance(v, dict):
            continue
        sev = str(v.get("severity") or "info").lower()
        buckets[sev] = buckets.get(sev, 0) + 1
    return buckets


def _recommendations_preview(doc: Dict[str, Any], limit: int = 8) -> List[Dict[str, str]]:
    raw = doc.get("recommendations") or []
    out: List[Dict[str, str]] = []
    for r in raw[:limit]:
        if not isinstance(r, dict):
            continue
        pri = _severity_str(r.get("priority"))
        out.append(
            {
                "priority": pri,
                "rationale": str(r.get("rationale") or "")[:400],
                "current_algorithm": str(r.get("current_algorithm") or ""),
                "recommended_algorithm": str(r.get("recommended_algorithm") or ""),
            }
        )
    return out


def extract_hostname_from_user_message(text: str) -> Optional[str]:
    """
    If the user did not fill the optional domain field but named a host in the message,
    use it for lookup so we do not fall back to 'latest scan for any domain'.
    """
    if not text:
        return None
    m = re.search(
        r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
        text.lower(),
    )
    if not m:
        return None
    return normalize_host_for_scan_lookup(m.group(1))


def resolve_copilot_scan_domain(message: str, explicit_domain: Optional[str]) -> Optional[str]:
    """Prefer the Domain field; otherwise infer a hostname from the user message."""
    d = normalize_host_for_scan_lookup(explicit_domain)
    if d:
        return d
    return extract_hostname_from_user_message(message or "")


async def build_copilot_context(db, scans_collection: str, domain: Optional[str]) -> Dict[str, Any]:
    """Summarize latest completed scan for LLM grounding; small token footprint."""
    try:
        payload, doc = await build_export_bundle_payload(db, scans_collection, domain)
    except LookupError:
        out: Dict[str, Any] = {
            "error": "no_completed_scan",
            "hint": "Run a scan from Overview and wait until status is completed.",
        }
        rd = normalize_host_for_scan_lookup(domain) if domain else None
        if rd:
            out["requested_domain"] = rd
        return out

    tls = payload.get("tls_results") or []
    cve = payload.get("cve_findings") or []
    vuln = payload.get("vuln_findings") or []
    qs = payload.get("quantum_score") or {}
    if isinstance(qs, dict):
        qscore = qs.get("score")
        qrisk = str(qs.get("risk_level") or "")
    else:
        qscore = None
        qrisk = ""

    tls_dist = _tls_protocol_distribution(tls if isinstance(tls, list) else [])
    cve_sev = _aggregate_cve_by_severity(cve if isinstance(cve, list) else [])
    vuln_sev = _aggregate_vuln_by_severity(vuln if isinstance(vuln, list) else [])
    rec_prev = _recommendations_preview(doc if isinstance(doc, dict) else {}, limit=8)

    return {
        "app": "QuantumShield",
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "completed_at": str(doc.get("completed_at") or ""),
        "quantum_score_0_100": qscore,
        "quantum_risk_level": qrisk,
        "counts": {
            "tls_endpoints": len(tls),
            "cve_mapped_findings": len(cve),
            "active_scan_findings": len(vuln),
        },
        "key_metrics": {
            "security_score_0_100": qscore,
            "risk_level": qrisk,
            "tls_endpoints": len(tls),
            "cve_findings_count": len(cve),
            "active_scan_findings_count": len(vuln),
        },
        "tls_protocol_distribution": tls_dist,
        "cve_by_severity": cve_sev,
        "vuln_by_severity": vuln_sev,
        "recommendations_preview": rec_prev,
        "sample_tls": [
            {
                "host": (t.get("host") or "")[:200],
                "tls_version": (t.get("tls_version") or "")[:80],
            }
            for t in (tls[:8] if isinstance(tls, list) else [])
        ],
        "notes": "Answer only using this context. Do not invent scan results.",
    }


def is_trivial_greeting(user_message: str) -> bool:
    q = (user_message or "").strip().lower()
    if re.match(r"^(hi|hello|hey|good\s+(morning|afternoon|evening))\b[!.?\s]*$", q):
        return True
    if len(q) <= 24 and q in ("hi", "hello", "hey", "yo", "sup"):
        return True
    return False


def _text_bar(filled: int, width: int = 10) -> str:
    filled = max(0, min(width, int(filled)))
    return "█" * filled + "░" * (width - filled)


def _score_to_bar_width(score: Optional[float]) -> int:
    if score is None:
        return 0
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 0
    return int(round(max(0.0, min(100.0, s)) / 10.0))


def _risk_to_bar_width(risk: str) -> int:
    r = (risk or "").lower()
    if "critical" in r:
        return 10
    if "high" in r:
        return 8
    if "medium" in r:
        return 5
    if "low" in r:
        return 3
    if "safe" in r:
        return 1
    return 4


def _pie_rows_from_counts(counts: Dict[str, int], label_title: str) -> List[str]:
    total = sum(counts.values())
    if total <= 0:
        return [f"• _Insufficient data for {label_title}._"]
    lines: List[str] = []
    for name, n in sorted(counts.items(), key=lambda x: -x[1]):
        pct = round(100.0 * n / total)
        blocks = max(1, int(round(10 * n / total)))
        lines.append(f"• **{name}** — {pct}% ({n}) {_text_bar(blocks, 10)}")
    return lines


def build_enterprise_dashboard_markdown(
    ctx: Dict[str, Any],
    user_message: str = "",
    *,
    compact: bool = False,
    offline_banner: bool = False,
) -> str:
    """
    Deterministic enterprise-style report (Markdown) for offline parity and JSON-echo fallback.
    Uses middle-dot bullets and [Icon: …] section labels per product spec.
    """
    if ctx.get("error") == "no_completed_scan":
        return (
            "• **No completed scan** in workspace. Run a scan from Overview and wait until it completes.\n\n"
            f"• {ctx.get('hint') or ''}"
        )

    km = ctx.get("key_metrics") if isinstance(ctx.get("key_metrics"), dict) else {}
    score = km.get("security_score_0_100")
    if score is None:
        score = ctx.get("quantum_score_0_100")
    risk = str(km.get("risk_level") or ctx.get("quantum_risk_level") or "—")
    domain = str(ctx.get("domain") or "—")
    scan_id = str(ctx.get("scan_id") or "—")
    completed = str(ctx.get("completed_at") or "—")
    counts = ctx.get("counts") if isinstance(ctx.get("counts"), dict) else {}
    tls_n = int(counts.get("tls_endpoints") or 0)
    cve_n = int(counts.get("cve_mapped_findings") or 0)
    vuln_n = int(counts.get("active_scan_findings") or 0)

    try:
        sf = float(score) if score is not None else None
    except (TypeError, ValueError):
        sf = None
    score_bar = _text_bar(_score_to_bar_width(sf))
    risk_bar = _text_bar(_risk_to_bar_width(risk))
    try:
        pct_label = f"{float(score):.1f}%" if score is not None else "n/a"
    except (TypeError, ValueError):
        pct_label = "n/a"

    lines: List[str] = []
    if offline_banner:
        lines.append("> **QuantumShield Copilot (offline)** — LM Studio unreachable; showing deterministic report.\n")

    lines.append("### [Icon: Dashboard] 1. Executive Summary")
    lines.append("")
    lines.append(f"• **Domain:** `{domain}`")
    lines.append(f"• **Scan ID:** `{scan_id}`")
    lines.append(f"• **Completed:** {completed}")
    lines.append(f"• **Security score (0–100):** {score if score is not None else '—'}")
    lines.append(f"• **Risk level:** {risk}")
    lines.append(f"• **TLS endpoints assessed:** {tls_n}")
    lines.append(f"• **CVE-mapped findings:** {cve_n}")
    lines.append(f"• **Active scan findings (e.g. Nuclei):** {vuln_n}")
    lines.append("")

    lines.append("### [Icon: BarChart] 2. Visual Metrics")
    lines.append("")
    lines.append("**Security score (text bar)**")
    lines.append("")
    lines.append(f"`{score_bar}`  {pct_label}")
    lines.append("")
    lines.append("**Risk posture (band bar)**")
    lines.append("")
    lines.append(f"`{risk_bar}`  {risk}")
    lines.append("")

    tls_dist = ctx.get("tls_protocol_distribution") if isinstance(ctx.get("tls_protocol_distribution"), dict) else {}
    if tls_dist and sum(tls_dist.values()) > 0:
        lines.append("### [Icon: PieChart] TLS protocol mix (share of endpoints)")
        lines.append("")
        lines.extend(_pie_rows_from_counts(tls_dist, "TLS mix"))
        lines.append("")

    cve_sev = ctx.get("cve_by_severity") if isinstance(ctx.get("cve_by_severity"), dict) else {}
    if cve_sev and sum(cve_sev.values()) > 0:
        lines.append("### [Icon: PieChart] CVE-mapped findings by severity")
        lines.append("")
        lines.extend(_pie_rows_from_counts(cve_sev, "CVE severity"))
        lines.append("")

    if compact:
        return "\n".join(lines).strip()

    lines.append("### [Icon: Search] 3. Detailed Analysis")
    lines.append("")
    lines.append("• **TLS configuration:** Negotiated protocol mix is summarized above; sample hosts:")
    samples = ctx.get("sample_tls") if isinstance(ctx.get("sample_tls"), list) else []
    for row in samples[:6]:
        if not isinstance(row, dict):
            continue
        h = str(row.get("host") or "").strip()
        tv = str(row.get("tls_version") or "").strip() or "—"
        if h:
            lines.append(f"  • `{h}` → {tv}")
    if not samples:
        lines.append("  • _No sample rows in context._")
    lines.append(f"• **Vulnerabilities (CVE pipeline):** {cve_n} mapped item(s).")
    lines.append(f"• **Endpoint / active signals:** {vuln_n} active scanner finding(s).")
    lines.append("")
    lines.append("_Beginner view:_ counts show exposure breadth. _Expert view:_ drill into CBOM and per-host TLS in the main app.")
    lines.append("")

    lines.append("### [Icon: Warning] 4. Risk Assessment")
    lines.append("")
    lines.append("• **Overall band:** " + risk)
    lines.append("• **Real-world impact (indicative):** weak TLS or legacy ciphers increase **MITM** and **downgrade** risk; CVE mappings highlight **known attack patterns** against those configurations.")
    lines.append("• **Data exposure:** TLS issues can enable **traffic decryption** where sessions are compromised.")
    lines.append("")

    lines.append("### [Icon: Build] 5. Recommendations (actionable)")
    lines.append("")
    recs = ctx.get("recommendations_preview") if isinstance(ctx.get("recommendations_preview"), list) else []
    hi, mid, low = [], [], []
    for r in recs:
        if not isinstance(r, dict):
            continue
        pri = str(r.get("priority") or "").lower()
        line = f"• **{r.get('current_algorithm', '')}** → **{r.get('recommended_algorithm', '')}:** {str(r.get('rationale') or '')[:280]}"
        if pri in ("critical", "high"):
            hi.append("[Icon: PriorityHigh] " + line)
        elif pri == "medium":
            mid.append("[Icon: Report] " + line)
        else:
            low.append("[Icon: CheckCircle] " + line)
    if hi:
        lines.append("**High priority**")
        lines.extend(hi[:5])
    if mid:
        lines.append("**Medium priority**")
        lines.extend(mid[:5])
    if low:
        lines.append("**Lower priority**")
        lines.extend(low[:5])
    if not recs:
        lines.append("• [Icon: CheckCircle] **No structured recommendations in context** — review TLS endpoints and CBOM in-app.")
    lines.append("")

    lines.append("### [Icon: Security] 6. Best practices")
    lines.append("")
    lines.append("• Enforce **TLS 1.3** (or 1.2 with strong ciphers) on all edge endpoints.")
    lines.append("• Rotate certificates before expiry; monitor **forward secrecy**.")
    lines.append("• Plan **PQC migration** aligned with organizational crypto policy (NIST PQC track).")
    lines.append("")

    return "\n".join(lines).strip()


def strip_scan_pipeline_diagram(text: str) -> str:
    """Remove scan pipeline / flow diagram section and any ```mermaid``` blocks from Copilot text."""
    t = (text or "").strip()
    if not t:
        return t
    t = re.sub(r"```\s*mermaid\s*[\s\S]*?```\s*", "", t, flags=re.IGNORECASE | re.DOTALL)
    # Drop "### … 7. … Scan Pipeline / Flow diagram …" through end of message
    t = re.sub(
        r"(?ms)^#{1,6}\s*(?:\[Icon:[^\]]+\]\s*)?7\.\s*(?:Scan Pipeline|Flow diagram)[^\n]*(?:\n[\s\S]*)?\Z",
        "",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(
        r"(?ms)^#{1,6}\s*7\.\s*Scan Pipeline Diagram[^\n]*(?:\n[\s\S]*)?\Z",
        "",
        t,
        flags=re.IGNORECASE,
    )
    # Plain numbered "7. Scan Pipeline…" (no heading markers) — strip through end of message
    t = re.sub(
        r"(?ms)(?:^|\n)\s*7\.\s*(?:Scan Pipeline|Flow diagram)[^\n]*(?:\n[\s\S]*)?\Z",
        "",
        t,
        flags=re.IGNORECASE,
    )
    return t.rstrip()


def postprocess_copilot_dashboard_reply(text: str, ctx: Dict[str, Any]) -> str:
    """Normalize Copilot reply; strip scan pipeline diagram (not shown to users)."""
    t = (text or "").strip()
    if ctx.get("error") == "no_completed_scan":
        return t
    return strip_scan_pipeline_diagram(t)


def looks_like_echoed_context_json(llm_text: str) -> bool:
    """
    Local/small LMs often echo CONTEXT_JSON back (sometimes in ```json fences).
    Detect that so we can substitute plain-language text.
    """
    t = (llm_text or "").strip()
    if len(t) < 30:
        return False

    inner = t
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", t, re.IGNORECASE)
    if m:
        inner = m.group(1).strip()

    if inner.startswith("{"):
        try:
            obj = json.loads(inner)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            if obj.get("app") == "QuantumShield" and isinstance(obj.get("counts"), dict):
                return True
            if {"quantum_score_0_100", "sample_tls", "counts"}.issubset(obj.keys()):
                return True

    tl = t.lower()
    if "```json" in tl:
        return True
    if '"quantum_score_0_100"' in t and '"sample_tls"' in t and '"counts"' in t:
        return True
    return False


def sanitize_copilot_llm_reply(llm_text: str, ctx: Dict[str, Any], user_message: str) -> str:
    """If the model dumped JSON/context, replace with deterministic enterprise dashboard Markdown."""
    if ctx.get("error") == "no_completed_scan":
        return copilot_no_database_records_reply(ctx)

    if not looks_like_echoed_context_json(llm_text):
        return (llm_text or "").strip()

    return (
        "> Raw JSON from the assistant was replaced with a readable report.\n\n"
        + build_enterprise_dashboard_markdown(
            ctx,
            user_message,
            compact=is_trivial_greeting(user_message),
            offline_banner=False,
        )
    ).strip()


def copilot_no_database_records_reply(ctx: Dict[str, Any]) -> str:
    """When no completed scan exists for the Copilot scope — do not use the LLM (avoids hallucinations)."""
    rd = ctx.get("requested_domain")
    if rd:
        return (
            "### [Icon: Warning] No database records\n\n"
            f"**No records available in the database** for `{rd}`. "
            "There is no **completed** scan stored for this domain.\n\n"
            "• Open **Overview**, enter this domain, start a **scan**, and wait until it **completes**. "
            "Then use the Copilot again for results grounded in your scan data."
        )
    return (
        "### [Icon: Warning] No database records\n\n"
        "**No records available in the database.** There is no completed scan to analyze yet.\n\n"
        "• Run a scan from **Overview** and wait until it completes, then try the Copilot again."
    )


def format_copilot_offline_reply(ctx: Dict[str, Any], user_message: str = "") -> str:
    """Deterministic enterprise dashboard when LM Studio is unreachable."""
    if ctx.get("error") == "no_completed_scan":
        return (
            "QuantumShield Copilot is offline (the local language model did not respond).\n\n"
            + copilot_no_database_records_reply(ctx)
        )

    compact = is_trivial_greeting(user_message)
    return build_enterprise_dashboard_markdown(
        ctx,
        user_message,
        compact=compact,
        offline_banner=True,
    ).strip()
