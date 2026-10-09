"""
QuantumShield — API Routes (v1 scanner + all dashboard endpoints)

Endpoints:
  POST /scan                      → trigger a full scan
  GET  /results/{domain}          → retrieve scan results
  GET  /cbom/{domain}             → retrieve CBOM report
  GET  /quantum-score/{domain}    → retrieve quantum readiness score
  GET  /security-roadmap/{domain}  → risk findings → target solutions (TLS + PQC migration)

  GET  /dashboard/summary         → dashboard KPI stats
  GET  /dashboard/policy-alignment → org policy vs latest scan TLS (indicative)
  GET  /dashboard/migration-snapshot → open tasks & pending waiver counts (Phase 5)
  GET  /dashboard/executive-brief   → stakeholder KPI rollup (Phase 6)
  GET  /dashboard/ops-snapshot      → DB + scan queue health (admin, Phase 7)
  GET  /assets                    → all discovered assets
  GET  /assets/stats              → asset type counts
  GET  /assets/distribution       → asset type distribution for pie chart
  GET  /cbom/summary              → CBOM summary stats
  GET  /cbom/charts               → CBOM chart data (key length, CA, protocols, cipher)
  GET  /dns/nameserver-records    → DNS nameserver records
  GET  /crypto/security           → crypto & TLS security overview
  GET  /pqc/posture               → PQC posture overview
  GET  /pqc/vulnerable-algorithms → list of vulnerable algorithms
  GET  /pqc/risk-categories       → PQC risk category scores
  GET  /pqc/compliance            → PQC compliance progress
  GET  /cyber-rating              → enterprise cyber rating (out of 1000)
  GET  /cyber-rating/risk-factors → risk factor breakdown
  GET  /reporting/domains         → list of scanned domains
  POST /reporting/generate        → generate a report
  GET  /reports/export-bundle     → JSON export (CBOM + TLS + score) for latest scan
  GET  /migration/roadmap         → phased migration waves (derived from scan)
  GET  /threat-model/summary      → Shor/Grover/HNDL context + scan counts
  GET  /threat-model/nist-catalog → NIST PQC publication URLs (FIPS 203/204/205)
  POST /quantum-score/simulate    → what-if score projection (TLS 1.3 / PQC hybrid assumptions)
  POST /scan/batch                → queue multiple domain scans (portfolio)
  GET  /scans/history             → completed scan list for a domain
  GET  /scans/recent              → recent scan jobs across all domains (portfolio)
  GET  /scans/diff                → compare two scans (new/removed hosts, TLS deltas)
  GET  /inventory/summary         → deduplicated hosts across recent scans
  POST /inventory/sources/import  → register external assets (CMDB/cloud/K8s/Git-style sources)
  GET  /inventory/registered      → list registered inventory rows
  POST /inventory/sbom            → attach SBOM JSON to a host (supply-chain / SAST path)
  PUT  /assets/metadata           → upsert host metadata (owner/env/criticality)
  POST /assets/metadata/bulk    → bulk metadata upsert
  GET  /discovery/assets          → discovered asset inventory (tabbed view)
  GET  /discovery/network-graph   → network graph nodes + edges
  POST /auth/login                → demo login (returns JWT-style token)
  GET  /admin/policy              → org crypto policy (Phase 4)
  PUT  /admin/policy              → update policy (admin)
  GET  /admin/integrations        → outbound webhooks (masked)
  PUT  /admin/integrations      → update integrations (admin)
  GET  /admin/exports/history     → export audit log
  POST /admin/exports/log         → record client-side export (audit)
  GET  /migration/tasks           → migration backlog tasks (Phase 5)
  POST /migration/tasks           → create task
  PATCH /migration/tasks/{id}     → update task
  DELETE /migration/tasks/{id}    → delete task (admin)
  POST /migration/tasks/seed-from-backlog → seed from scan backlog (admin)
  GET  /migration/waivers         → crypto waivers / exceptions
  POST /migration/waivers         → request waiver
  PATCH /migration/waivers/{id}   → update (approve/reject: admin)
  DELETE /migration/waivers/{id}  → delete (admin)
"""

import asyncio
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pymongo import ReturnDocument

from app.config import settings
from app.core.deps import get_current_user, require_admin, require_employee_only
from app.db.connection import get_database
from app.db.models import (
    AssetMetadataUpdate,
    BatchScanRequest,
    InventorySourceImport,
    IntegrationSettingsUpdate,
    ExportAuditLogCreate,
    ReportScheduleCreate,
    ReportSchedulePatch,
    AiRoadmapPlanBody,
    AiCopilotChatBody,
    NotificationCreate,
    NotificationMarkRead,
    MigrationTaskCreate,
    MigrationTaskUpdate,
    OrgCryptoPolicyUpdate,
    SeedTasksFromBacklogBody,
    SimulateQuantumRequest,
    User,
    WaiverCreate,
    WaiverUpdate,
    CBOMReport,
    CryptoComponent,
    QuantumScore,
    Recommendation,
    SbomIngestRequest,
    ScanRequest,
    ScanResult,
    ScanStatus,
    RiskLevel,
    TLSInfo,
    AlgorithmCategory,
    QuantumStatus,
)
from app.modules import (
    asset_discovery,
    tls_scanner,
    crypto_analyzer,
    quantum_risk_engine,
    cbom_generator,
    recommendation_engine,
)
from app.modules.headers_scanner import scan_headers
from app.modules.asset_classification import enrich_discovered_assets
from app.modules.threat_nist_mapping import (
    NIST_PQC_REFERENCES,
    build_prioritized_backlog,
    enrich_cbom_component_dict,
    simulate_quantum_score,
)
from app.scanner.roadmap.facade import build_roadmap_from_scan
from app.modules.report_bundle import build_export_bundle_payload
from app.modules.report_scheduler import (
    REPORT_SCHEDULES_COLLECTION,
    MAIL_LOG_COLLECTION,
    REPORT_ARTIFACTS_COLLECTION,
    execute_schedule_run,
    scheduler_loop,
    compute_next_fire,
    artifact_file_path,
)
from app.modules.lm_studio_client import chat_completion, chat_completion_safe
from app.modules.roadmap_ai_plan import build_deterministic_roadmap_plan_text
from app.modules.copilot_context import (
    build_copilot_context,
    copilot_no_database_records_reply,
    format_copilot_offline_reply,
    is_trivial_greeting,
    postprocess_copilot_dashboard_reply,
    resolve_copilot_scan_domain,
    sanitize_copilot_llm_reply,
)
from app.modules.scan_lifecycle import (
    find_active_scan_for_domain,
    find_reusable_terminal_scan_for_domain,
    normalize_domain_for_scan,
    reset_scan_document_for_rerun,
    variants_for_scan_domain,
)
from app.modules.webhook_notify import post_json_webhook, post_slack_incoming_webhook
from app.core.ws_manager import manager as ws_manager
from app.utils.asset_type import asset_type_label, classify_asset_service
from app.utils.ca_display_name import (
    extract_issuer_raw_from_tls_row,
    normalize_ca_display_name,
)
from app.utils.logger import get_logger
from app.utils.policy_alignment import summarize_tls_vs_policy

logger = get_logger(__name__)

router = APIRouter(tags=["Scanner"])
from .common import *
from .common import _DEFAULT_ORG_POLICY, _DEFAULT_INTEGRATION, _integration_public_view



@router.get("/reporting/domains", tags=["Admin"])
async def get_reporting_domains():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, {"domain": 1}
    ).to_list(length=50)
    domains = list({s["domain"] for s in scans if "domain" in s})
    return domains


@router.post("/reporting/generate", tags=["Admin"])
async def generate_report(payload: dict):
    domain = payload.get("domain", "")
    report_type = payload.get("reportType", "executive")
    fmt = payload.get("format", "PDF")
    return {
        "status": "success",
        "message": f"{fmt} report generated for {domain}",
        "report_type": report_type,
        "download_url": f"/reports/{domain}_{report_type}.{fmt.lower()}",
    }


@router.get("/reports/export-bundle", tags=["Admin"])
async def export_scan_bundle(domain: Optional[str] = None):
    """Single JSON for audits: latest completed scan, optional domain filter."""
    db = get_database()
    try:
        payload, doc = await build_export_bundle_payload(db, SCANS_COLLECTION, domain)
    except LookupError:
        raise HTTPException(status_code=404, detail="No completed scan found")
    try:
        await db[EXPORT_AUDIT_COLLECTION].insert_one(
            {
                "event_id": uuid.uuid4().hex,
                "export_type": "scan_bundle_json",
                "domain": doc.get("domain"),
                "created_at": datetime.utcnow(),
            }
        )
    except Exception as exc:
        logger.warning("Export audit log insert failed: %s", exc)

    return payload


@router.get("/migration/roadmap", tags=["Admin"])
async def get_migration_roadmap(domain: Optional[str] = None):
    db = get_database()
    query: dict = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scan = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not scan:
        return {"domain": None, "waves": [], "backlog": [], "nist_pqc_references": NIST_PQC_REFERENCES}

    tls = scan.get("tls_results", [])
    legacy_ver = {"TLSv1.0", "TLSv1.1", "TLSv1", "SSLv3", "SSLv2"}
    crit_tls = sum(
        1
        for t in tls
        if (t.get("tls_version") or "") in legacy_ver
        or (not t.get("tls_version") and t.get("host"))
    )
    expiring = sum(
        1
        for t in tls
        if (t.get("certificate") or {}).get("days_until_expiry", 999) <= 30
    )
    n = max(len(tls), 1)
    meta_by_host: dict = {}
    for a in scan.get("assets") or []:
        h = (a.get("subdomain") or "").strip().lower()
        if not h:
            continue
        mdoc = await db[ASSET_METADATA_COLLECTION].find_one({"host": h})
        if mdoc:
            meta_by_host[h] = mdoc

    backlog = build_prioritized_backlog(scan, meta_by_host)

    waves_raw = [
        {
            "wave": 1,
            "name": "Stabilize & certificate hygiene",
            "focus": "Expiring certificates and legacy TLS endpoints",
            "estimated_assets": min(expiring + crit_tls, n),
            "nist_alignment": "SP 800-208 TLS hygiene; interim classical hardening",
        },
        {
            "wave": 2,
            "name": "TLS modernization",
            "focus": "Prefer TLS 1.3 and strong cipher suites across endpoints",
            "estimated_assets": len(tls),
            "nist_alignment": "FIPS 203-ready hybrid KEM profiles as libraries mature",
        },
        {
            "wave": 3,
            "name": "PQC readiness",
            "focus": "Plan hybrid / PQC algorithms as libraries and CAs adopt them",
            "estimated_assets": len(scan.get("assets", [])) or n,
            "nist_alignment": "FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)",
        },
    ]
    waves = []
    for w in waves_raw:
        est = int(w.get("estimated_assets") or 0)
        waves.append({**w, "priority_score": round(est * (4 - w["wave"]) / max(n, 1), 3)})

    return {
        "domain": scan.get("domain"),
        "waves": waves,
        "backlog": backlog,
        "nist_pqc_references": NIST_PQC_REFERENCES,
    }


@router.get("/admin/policy", tags=["Admin"])
async def get_org_policy(_user: User = Depends(get_current_user)):
    db = get_database()
    doc = await db[ORG_POLICY_COLLECTION].find_one({"_id": "default"})
    if not doc:
        return {**_DEFAULT_ORG_POLICY, "updated_at": None}
    out = {**_DEFAULT_ORG_POLICY}
    for k in out:
        if k in doc and doc[k] is not None:
            out[k] = doc[k]
    out["updated_at"] = doc.get("updated_at")
    return out


@router.put("/admin/policy", tags=["Admin"])
async def put_org_policy(
    body: OrgCryptoPolicyUpdate,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    cur = await db[ORG_POLICY_COLLECTION].find_one({"_id": "default"})
    merged = {**_DEFAULT_ORG_POLICY}
    if cur:
        for k in merged:
            if k in cur and cur[k] is not None:
                merged[k] = cur[k]
    for k, v in body.model_dump(exclude_unset=True).items():
        merged[k] = v
    merged["_id"] = "default"
    merged["updated_at"] = datetime.utcnow()
    await db[ORG_POLICY_COLLECTION].replace_one({"_id": "default"}, merged, upsert=True)
    merged.pop("_id", None)
    return merged


@router.get("/admin/integrations", tags=["Admin"])
async def get_integrations(_user: User = Depends(get_current_user)):
    db = get_database()
    doc = await db[INTEGRATION_SETTINGS_COLLECTION].find_one({"_id": "default"})
    if not doc:
        return _integration_public_view({"_id": "default", **_DEFAULT_INTEGRATION})
    return _integration_public_view(doc)


@router.put("/admin/integrations", tags=["Admin"])
async def put_integrations(
    body: IntegrationSettingsUpdate,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    cur = await db[INTEGRATION_SETTINGS_COLLECTION].find_one({"_id": "default"})
    merged = {**_DEFAULT_INTEGRATION}
    if cur:
        for k in merged:
            if k in cur:
                merged[k] = cur[k]
    for k, v in body.model_dump(exclude_unset=True).items():
        merged[k] = v
    merged["_id"] = "default"
    merged["updated_at"] = datetime.utcnow()
    await db[INTEGRATION_SETTINGS_COLLECTION].replace_one({"_id": "default"}, merged, upsert=True)
    return _integration_public_view(merged)


@router.get("/admin/exports/history", tags=["Admin"])
async def get_export_audit_history(limit: int = 50, _user: User = Depends(get_current_user)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[EXPORT_AUDIT_COLLECTION].find().sort("created_at", -1).limit(lim)
    events: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        events.append(row)
    return {"count": len(events), "events": events}


@router.post("/admin/exports/log", tags=["Admin"])
async def post_export_audit_log(
    body: ExportAuditLogCreate,
    user: User = Depends(get_current_user),
):
    """When the UI downloads roadmap/threat JSON client-side, it can log the event here."""
    db = get_database()
    doc = {
        "event_id": uuid.uuid4().hex,
        "export_type": body.export_type.strip()[:80],
        "domain": (body.domain or "").strip().lower() or None,
        "created_at": datetime.utcnow(),
        "actor": user.email,
    }
    await db[EXPORT_AUDIT_COLLECTION].insert_one(doc)
    out = {k: v for k, v in doc.items() if k != "_id"}
    return out


@router.get("/admin/report-schedules", tags=["Admin"])
async def list_report_schedules(_admin: User = Depends(require_admin)):
    db = get_database()
    cursor = db[REPORT_SCHEDULES_COLLECTION].find().sort("created_at", -1).limit(100)
    items: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        items.append(row)
    return {"count": len(items), "schedules": items}


@router.post("/admin/report-schedules", tags=["Admin"])
async def create_report_schedule(body: ReportScheduleCreate, admin: User = Depends(require_admin)):
    db = get_database()
    if not body.delivery.email_enabled and not body.delivery.download_enabled:
        raise HTTPException(
            status_code=400,
            detail="Enable at least one delivery option: email and/or download.",
        )
    schedule_id = uuid.uuid4().hex
    now = datetime.utcnow()
    dom = (body.domain or "").strip().lower() or None
    next_run = compute_next_fire(body.cadence, body.hour_utc, body.minute_utc, now)
    doc = {
        "schedule_id": schedule_id,
        "domain": dom,
        "cadence": body.cadence,
        "hour_utc": body.hour_utc,
        "minute_utc": body.minute_utc,
        "enabled": body.enabled,
        "delivery": body.delivery.model_dump(),
        "created_at": now,
        "created_by": admin.email,
        "next_run_at": next_run,
        "last_run_at": None,
        "last_error": None,
    }
    await db[REPORT_SCHEDULES_COLLECTION].insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.patch("/admin/report-schedules/{schedule_id}", tags=["Admin"])
async def patch_report_schedule(
    schedule_id: str,
    body: ReportSchedulePatch,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    cur = await db[REPORT_SCHEDULES_COLLECTION].find_one({"schedule_id": schedule_id})
    if not cur:
        raise HTTPException(status_code=404, detail="Schedule not found")
    patch: Dict[str, Any] = {}
    if body.domain is not None:
        patch["domain"] = (body.domain or "").strip().lower() or None
    if body.cadence is not None:
        patch["cadence"] = body.cadence
    if body.hour_utc is not None:
        patch["hour_utc"] = body.hour_utc
    if body.minute_utc is not None:
        patch["minute_utc"] = body.minute_utc
    if body.enabled is not None:
        patch["enabled"] = body.enabled
    if body.delivery is not None:
        d = body.delivery.model_dump()
        if not d.get("email_enabled") and not d.get("download_enabled"):
            raise HTTPException(
                status_code=400,
                detail="Enable at least one delivery option: email and/or download.",
            )
        patch["delivery"] = d
    if patch:
        now = datetime.utcnow()
        cadence = str(patch.get("cadence", cur.get("cadence") or "daily"))
        hour_utc = int(patch.get("hour_utc", cur.get("hour_utc") or 6))
        minute_utc = int(patch.get("minute_utc", cur.get("minute_utc") or 0))
        patch["next_run_at"] = compute_next_fire(cadence, hour_utc, minute_utc, now)
        await db[REPORT_SCHEDULES_COLLECTION].update_one({"schedule_id": schedule_id}, {"$set": patch})
    out = await db[REPORT_SCHEDULES_COLLECTION].find_one({"schedule_id": schedule_id})
    if out:
        out.pop("_id", None)
    return out


@router.delete("/admin/report-schedules/{schedule_id}", tags=["Admin"])
async def delete_report_schedule(schedule_id: str, _admin: User = Depends(require_admin)):
    db = get_database()
    r = await db[REPORT_SCHEDULES_COLLECTION].delete_one({"schedule_id": schedule_id})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"ok": True}


@router.post("/admin/report-schedules/{schedule_id}/run-now", tags=["Admin"])
async def run_report_schedule_now(schedule_id: str, _admin: User = Depends(require_admin)):
    db = get_database()
    sched = await db[REPORT_SCHEDULES_COLLECTION].find_one({"schedule_id": schedule_id})
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await execute_schedule_run(sched, manual=True)
    return {"ok": True}


@router.get("/admin/mail-log", tags=["Admin"])
async def get_mail_log(limit: int = 50, _admin: User = Depends(require_admin)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[MAIL_LOG_COLLECTION].find().sort("created_at", -1).limit(lim)
    rows: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        rows.append(row)
    return {"count": len(rows), "events": rows}


@router.get("/admin/report-artifacts", tags=["Admin"])
async def list_report_artifacts(limit: int = 50, _user: User = Depends(get_current_user)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[REPORT_ARTIFACTS_COLLECTION].find().sort("created_at", -1).limit(lim)
    rows: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        rows.append(row)
    return {"count": len(rows), "artifacts": rows}


@router.get("/admin/report-artifacts/{artifact_id}/download", tags=["Admin"])
async def download_report_artifact(artifact_id: str, _user: User = Depends(get_current_user)):
    db = get_database()
    doc = await db[REPORT_ARTIFACTS_COLLECTION].find_one({"artifact_id": artifact_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Artifact not found")
    fn = doc.get("filename")
    if not fn:
        raise HTTPException(status_code=404, detail="Invalid artifact")
    path = artifact_file_path(str(fn))
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File missing on server")
    return FileResponse(path, filename=fn, media_type="application/json")


@router.post("/ai/roadmap/plan", tags=["AI"])
async def ai_roadmap_plan(body: AiRoadmapPlanBody, _user: User = Depends(get_current_user)):
    db = get_database()
    d = body.domain.strip().lower()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": d, "status": ScanStatus.COMPLETED.value},
        sort=[("completed_at", -1), ("started_at", -1)],
    )
    if not doc:
        doc = await db[SCANS_COLLECTION].find_one({"domain": d}, sort=[("started_at", -1)])
    if not doc:
        raise HTTPException(status_code=404, detail=f"No scan results found for domain: {body.domain}")

    roadmap = await build_roadmap_from_scan(db, doc)
    items = [item.model_dump() for item in roadmap.items][:80]
    q = doc.get("quantum_score") or {}
    det: Dict[str, Any] = {
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "scan_status": doc.get("status"),
        "completed_at": str(doc.get("completed_at") or ""),
        "quantum_risk_level": q.get("risk_level"),
        "quantum_score": q.get("score"),
        "items": items,
    }
    horizon = None
    notes = ""
    if body.constraints and isinstance(body.constraints, dict):
        horizon = body.constraints.get("horizon_days")
        notes = str(body.constraints.get("notes") or "")[:500]

    deterministic_plan = build_deterministic_roadmap_plan_text(det, horizon, notes)
    system = (
        "You are QuantumShield roadmap planner. Use ONLY the JSON context. "
        "Write a concrete migration plan as bullet lines starting with '- ' (Markdown). "
        "Group into three time phases (e.g. days 1–30, 31–60, 61–90) or similar; reference real "
        "risks and solutions from context.items by paraphrasing them — do not invent hosts, CVEs, or findings "
        "not in context. Keep each bullet scannable; no JSON echo."
    )
    user_msg = (
        f"Context JSON:\n{json.dumps(det, default=str)[:14000]}\n\n"
        f"Horizon_days hint: {horizon}\nNotes: {notes}\n"
    )

    plan_source = "llm"
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user_msg}]
    try:
        ai_text = await chat_completion(messages, temperature=0.25, max_tokens=3072)
        if not (ai_text or "").strip():
            raise RuntimeError("empty LLM content")
    except Exception:
        ai_text = deterministic_plan
        plan_source = "deterministic"

    bullets = [ln.strip() for ln in ai_text.splitlines() if ln.strip().startswith("-")]
    if not bullets:
        bullets = [ln.strip() for ln in ai_text.splitlines() if ln.strip()][:25]

    disclaimer = (
        "Indicative guidance derived from external scan signals; validate with architecture, "
        "application, and PKI owners before production or compliance commitments."
    )
    return {
        "deterministic_items": items,
        "ai_plan_text": ai_text,
        "ai_bullets": bullets[:40],
        "disclaimer": disclaimer,
        "plan_source": plan_source,
    }


@router.post("/ai/copilot/chat", tags=["AI"])
async def ai_copilot_chat(body: AiCopilotChatBody, _user: User = Depends(get_current_user)):
    db = get_database()
    dom = resolve_copilot_scan_domain(body.message, body.domain)
    ctx = await build_copilot_context(db, SCANS_COLLECTION, dom)
    if ctx.get("error") == "no_completed_scan":
        reply = postprocess_copilot_dashboard_reply(
            copilot_no_database_records_reply(ctx),
            ctx,
        )
        return {"reply": reply, "context_used": ctx}

    compact = is_trivial_greeting(body.message)
    mode_note = (
        "OUTPUT MODE: COMPACT — include sections 1 (Executive Summary) and 2 (Visual Metrics with text bar charts). "
        "Omit sections 3–6.\n\n"
        if compact
        else "OUTPUT MODE: FULL — include ALL numbered sections 1 through 6 below.\n\n"
    )
    system = (
        "You are a senior cybersecurity analyst and UI-focused technical communicator for QuantumShield. "
        "You receive CONTEXT_JSON with scan facts. Answer ONLY using CONTEXT_JSON; do not invent hosts, CVEs, or numbers.\n\n"
        "Formatting rules (mandatory):\n"
        "• Use structured Markdown with ### headings. Each section starts with a label like "
        "### [Icon: Dashboard] 1. Executive Summary — use these icon tags as plain text: "
        "[Icon: Dashboard], [Icon: BarChart], [Icon: PieChart], [Icon: Search], [Icon: Warning], [Icon: Build], "
        "[Icon: Security], [Icon: AccountTree], [Icon: PriorityHigh], [Icon: Report], [Icon: CheckCircle].\n"
        "• Use bullet lines starting with • (middle dot) or Markdown list syntax. No emojis.\n"
        "• Avoid long paragraphs; prefer scannable bullets.\n"
        "• Section 2 must include text-based bar charts for Security score and Risk level using block characters "
        "(e.g. █ and ░), scaled from CONTEXT_JSON key_metrics / quantum_score_0_100 and quantum_risk_level.\n"
        "• When tls_protocol_distribution or cve_by_severity in CONTEXT_JSON support it, add compact text 'pie' rows "
        "(percent + small bar). If distributions are empty, say insufficient data.\n"
        "• Section 3: TLS configuration, vulnerabilities (CVE), endpoint/active findings — beginner-friendly plus a one-line expert cue.\n"
        "• Section 4: Risk assessment with Low/Medium/High framing and real-world impact (MITM, downgrade, exposure) only as grounded commentary.\n"
        "• Section 5: Prioritize recommendations using [Icon: PriorityHigh], [Icon: Report], [Icon: CheckCircle] from "
        "recommendations_preview when present.\n"
        "• Section 6: Best practices (TLS 1.3, cert hygiene, PQC planning). End the report after section 6; "
        "do not add a scan pipeline diagram, flowchart, or Mermaid.\n"
        "• Do NOT echo CONTEXT_JSON. Do NOT use ```json fences. Do not use ```mermaid or any diagram blocks.\n"
        "• If the user asks about anything not in CONTEXT_JSON, reply with a single short paragraph or bullet: "
        "I can only discuss QuantumShield scan results available in your workspace context.\n"
    )
    user_msg = (
        f"{mode_note}"
        f"CONTEXT_JSON:\n{json.dumps(ctx, default=str)[:12000]}\n\nUSER:\n{body.message}"
    )
    reply = await chat_completion_safe(
        [{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
        fallback=format_copilot_offline_reply(ctx, body.message),
    )
    reply = postprocess_copilot_dashboard_reply(sanitize_copilot_llm_reply(reply, ctx, body.message), ctx)
    return {"reply": reply, "context_used": ctx}


@router.post("/notifications", tags=["Notifications"])
async def create_employee_notification(
    body: NotificationCreate,
    sender: User = Depends(require_employee_only),
):
    db = get_database()
    notification_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    doc = {
        "notification_id": notification_id,
        "from_user_id": sender.id,
        "from_email": (sender.email or "").strip().lower(),
        "from_name": (sender.full_name or "").strip() or None,
        "to_role": "admin",
        "subject": body.subject.strip(),
        "body": body.body.strip(),
        "category": body.category,
        "created_at": now,
        "read_at": None,
        "read_by": None,
    }
    await db[NOTIFICATIONS_COLLECTION].insert_one(doc)
    return _notification_public(doc)


@router.get("/notifications/me", tags=["Notifications"])
async def list_my_notifications(
    limit: int = 40,
    skip: int = 0,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    lim = min(max(limit, 1), 200)
    sk = max(skip, 0)
    email = (_user.email or "").strip().lower()
    q = {"from_email": email}
    cursor = (
        db[NOTIFICATIONS_COLLECTION]
        .find(q)
        .sort([("created_at", -1)])
        .skip(sk)
        .limit(lim)
    )
    items: List[Dict[str, Any]] = []
    async for row in cursor:
        items.append(_notification_public(row))
    total = await db[NOTIFICATIONS_COLLECTION].count_documents(q)
    return {"count": len(items), "total": total, "notifications": items}


@router.get("/admin/notifications", tags=["Notifications"])
async def list_admin_notifications(
    limit: int = 40,
    skip: int = 0,
    unread_only: bool = False,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    lim = min(max(limit, 1), 200)
    sk = max(skip, 0)
    q: Dict[str, Any] = {}
    if unread_only:
        q["read_at"] = None
    cursor = (
        db[NOTIFICATIONS_COLLECTION]
        .find(q)
        .sort([("created_at", -1)])
        .skip(sk)
        .limit(lim)
    )
    items: List[Dict[str, Any]] = []
    async for row in cursor:
        items.append(_notification_public(row))
    total = await db[NOTIFICATIONS_COLLECTION].count_documents(q)
    return {"count": len(items), "total": total, "notifications": items}


@router.patch("/admin/notifications/{notification_id}", tags=["Notifications"])
async def mark_notification_read(
    notification_id: str,
    body: NotificationMarkRead,
    admin: User = Depends(require_admin),
):
    if not body.read:
        raise HTTPException(status_code=400, detail="Only read=true is supported")
    db = get_database()
    now = datetime.now(timezone.utc)
    res = await db[NOTIFICATIONS_COLLECTION].find_one_and_update(
        {"notification_id": notification_id},
        {
            "$set": {
                "read_at": now,
                "read_by": (admin.email or "").strip().lower(),
            }
        },
        return_document=ReturnDocument.AFTER,
    )
    if not res:
        raise HTTPException(status_code=404, detail="Notification not found")
    return _notification_public(res)


@router.get("/migration/tasks", tags=["Migration"])
async def list_migration_tasks(
    domain: Optional[str] = None,
    status_filter: Optional[str] = None,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    q: dict = {}
    if domain:
        q["domain"] = domain.strip().lower()
    if status_filter:
        q["status"] = status_filter
    cursor = db[MIGRATION_TASKS_COLLECTION].find(q).sort("updated_at", -1).limit(500)
    items: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        items.append(row)
    return {"count": len(items), "tasks": items}


@router.post("/migration/tasks", tags=["Migration"])
async def create_migration_task(
    body: MigrationTaskCreate,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    task_id = uuid.uuid4().hex
    now = datetime.utcnow()
    doc = {
        "task_id": task_id,
        "title": body.title.strip(),
        "description": body.description,
        "domain": (body.domain or "").strip().lower() or None,
        "host": (body.host or "").strip().lower() or None,
        "wave": body.wave,
        "priority": body.priority,
        "status": body.status,
        "due_date": body.due_date,
        "owner": body.owner,
        "created_at": now,
        "updated_at": now,
    }
    await db[MIGRATION_TASKS_COLLECTION].insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.patch("/migration/tasks/{task_id}", tags=["Migration"])
async def update_migration_task(
    task_id: str,
    body: MigrationTaskUpdate,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    patch = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not patch:
        doc = await db[MIGRATION_TASKS_COLLECTION].find_one({"task_id": task_id})
        if not doc:
            raise HTTPException(status_code=404, detail="Task not found")
        doc.pop("_id", None)
        return doc
    patch["updated_at"] = datetime.utcnow()
    r = await db[MIGRATION_TASKS_COLLECTION].find_one_and_update(
        {"task_id": task_id},
        {"$set": patch},
        return_document=ReturnDocument.AFTER,
    )
    if not r:
        raise HTTPException(status_code=404, detail="Task not found")
    r.pop("_id", None)
    return r


@router.delete("/migration/tasks/{task_id}", tags=["Migration"])
async def delete_migration_task(
    task_id: str,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    res = await db[MIGRATION_TASKS_COLLECTION].delete_one({"task_id": task_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok", "task_id": task_id}


@router.post("/migration/tasks/seed-from-backlog", tags=["Migration"])
async def seed_tasks_from_backlog(
    body: SeedTasksFromBacklogBody,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    query: dict = {"status": "completed"}
    if body.domain:
        query["domain"] = body.domain.strip().lower()
    scan = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not scan:
        raise HTTPException(status_code=404, detail="No completed scan found")

    meta_by_host: dict = {}
    for a in scan.get("assets") or []:
        h = (a.get("subdomain") or "").strip().lower()
        if not h:
            continue
        mdoc = await db[ASSET_METADATA_COLLECTION].find_one({"host": h})
        if mdoc:
            meta_by_host[h] = mdoc

    backlog = build_prioritized_backlog(scan, meta_by_host)[: body.limit]
    now = datetime.utcnow()
    created: List[dict] = []
    for item in backlog:
        host = item.get("host") or ""
        exists = await db[MIGRATION_TASKS_COLLECTION].find_one(
            {
                "host": host,
                "domain": scan.get("domain"),
                "status": {"$in": ["open", "in_progress"]},
            }
        )
        if exists:
            continue
        task_id = uuid.uuid4().hex
        pri = float(item.get("priority_score") or 0)
        doc = {
            "task_id": task_id,
            "title": f"Remediate {host}",
            "description": item.get("reason") or item.get("nist_primary_recommendation"),
            "domain": scan.get("domain"),
            "host": host,
            "wave": 1,
            "priority": "critical" if pri > 18 else "high" if pri > 10 else "medium",
            "status": "open",
            "due_date": None,
            "owner": item.get("owner"),
            "source": "backlog_seed",
            "created_at": now,
            "updated_at": now,
        }
        await db[MIGRATION_TASKS_COLLECTION].insert_one(doc)
        doc.pop("_id", None)
        created.append(doc)

    return {"scan_domain": scan.get("domain"), "seeded": len(created), "tasks": created}


@router.get("/migration/waivers", tags=["Migration"])
async def list_waivers(
    status_filter: Optional[str] = None,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    q: dict = {}
    if status_filter:
        q["status"] = status_filter
    cursor = db[WAIVERS_COLLECTION].find(q).sort("created_at", -1).limit(200)
    items: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        items.append(row)
    return {"count": len(items), "waivers": items}


@router.post("/migration/waivers", tags=["Migration"])
async def create_waiver(
    body: WaiverCreate,
    _user: User = Depends(get_current_user),
):
    db = get_database()
    waiver_id = uuid.uuid4().hex
    now = datetime.utcnow()
    doc = {
        "waiver_id": waiver_id,
        "requestor": body.requestor.strip(),
        "reason": body.reason.strip(),
        "expiry": body.expiry,
        "impacted_assets": body.impacted_assets or [],
        "status": body.status if body.status in ("pending", "draft") else "pending",
        "created_by": _user.email,
        "created_at": now,
        "updated_at": now,
    }
    await db[WAIVERS_COLLECTION].insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.patch("/migration/waivers/{waiver_id}", tags=["Migration"])
async def update_waiver(
    waiver_id: str,
    body: WaiverUpdate,
    user: User = Depends(get_current_user),
):
    db = get_database()
    patch = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    st = patch.get("status")
    if st in ("approved", "rejected") and user.role.lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can approve or reject waivers.",
        )
    if not patch:
        doc = await db[WAIVERS_COLLECTION].find_one({"waiver_id": waiver_id})
        if not doc:
            raise HTTPException(status_code=404, detail="Waiver not found")
        doc.pop("_id", None)
        return doc
    patch["updated_at"] = datetime.utcnow()
    r = await db[WAIVERS_COLLECTION].find_one_and_update(
        {"waiver_id": waiver_id},
        {"$set": patch},
        return_document=ReturnDocument.AFTER,
    )
    if not r:
        raise HTTPException(status_code=404, detail="Waiver not found")
    r.pop("_id", None)
    return r


@router.delete("/migration/waivers/{waiver_id}", tags=["Migration"])
async def delete_waiver(
    waiver_id: str,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    res = await db[WAIVERS_COLLECTION].delete_one({"waiver_id": waiver_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Waiver not found")
    return {"status": "ok", "waiver_id": waiver_id}
