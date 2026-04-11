"""
Scan-grounded roadmap plan text when the local LLM is unavailable, plus helpers for /ai/roadmap/plan.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4}


def _pri_rank(p: Optional[str]) -> int:
    return _PRIORITY.get(str(p or "medium").lower(), 2)


def _item_bullet(it: Dict[str, Any]) -> str:
    risk = str(it.get("risk") or "Finding").strip()
    sol = str(it.get("solution") or "").strip()
    pri = str(it.get("priority") or "medium")
    cat = str(it.get("category") or "").strip()
    tail = f" — {sol}" if sol else ""
    extra = f" [{cat}]" if cat else ""
    line = f"- **[{pri}]{extra} {risk}**{tail}"
    return line[:650]


def build_deterministic_roadmap_plan_text(
    det: Dict[str, Any],
    horizon_days: Optional[Any],
    notes: str,
) -> str:
    """Rich '- ' bullet plan from the same JSON context as the LLM — unique per scan."""
    items = [x for x in (det.get("items") or []) if isinstance(x, dict)]
    domain = str(det.get("domain") or "domain")
    qr = str(det.get("quantum_risk_level") or "unknown")
    qs = det.get("quantum_score")
    sid = str(det.get("scan_id") or "")
    sid_short = (sid[:14] + "…") if len(sid) > 14 else sid

    lines: List[str] = []
    intro = f"- **Scan snapshot** (`{domain}`" + (f", `{sid_short}`" if sid else "")
    intro += f"): quantum risk **{qr}**"
    if qs is not None:
        intro += f", engine score **{qs}**/100"
    intro += "."
    lines.append(intro)

    if notes.strip():
        lines.append(f"- **Your notes:** {notes.strip()[:450]}")

    if horizon_days is not None:
        try:
            hd = int(horizon_days)
            if 1 <= hd <= 3650:
                lines.append(
                    f"- **Horizon:** {hd} days — phases below split the work into three windows over that period."
                )
        except (TypeError, ValueError):
            pass

    if not items:
        lines.append(
            "- No roadmap rows were derived from this scan yet — run a full scan or verify TLS endpoints were probed."
        )
        return "\n".join(lines)

    ranked = sorted(items, key=lambda i: (_pri_rank(i.get("priority")), str(i.get("id") or "")))

    n = len(ranked)
    third = max(1, (n + 2) // 3)
    phase1 = ranked[:third]
    phase2 = ranked[third : third * 2]
    phase3 = ranked[third * 2 :]

    def emit_phase(header: str, chunk: List[Dict[str, Any]]) -> None:
        if not chunk:
            return
        lines.append(header)
        for it in chunk[:12]:
            lines.append(_item_bullet(it))

    emit_phase("- **Phase 1 (first third — stabilize & quick wins):**", phase1)
    emit_phase("- **Phase 2 (middle third — remediation & rollout):**", phase2)
    emit_phase("- **Phase 3 (final third — harden & PQC alignment):**", phase3)

    if n > 36:
        lines.append(f"- _({n - 36} more rows in the full deterministic list below.)_")

    return "\n".join(lines)
