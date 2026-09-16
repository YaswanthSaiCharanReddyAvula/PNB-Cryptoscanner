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
from app.modules.cve_mapper import map_cves
from app.modules.asset_classification import enrich_discovered_assets
from app.modules.vuln_scanner import run_nuclei_scan
from app.modules.threat_nist_mapping import (
    NIST_PQC_REFERENCES,
    build_prioritized_backlog,
    enrich_cbom_component_dict,
    simulate_quantum_score,
)
from app.modules.security_roadmap import build_security_roadmap
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



@router.post("/scan/fix-stale", tags=["Scanner"])
async def fix_stale_scans():
    db = get_database()
    r = await db[SCANS_COLLECTION].update_many(
        {"status": {"$in": ["running", "pending"]}},
        {"$set": {"status": "failed", "error": "Cleared stale scan for rescan"}}
    )
    return {"cleared": r.modified_count}


@router.post("/scan", tags=["Scanner"])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start an asynchronous scan of the given domain."""
    db = get_database()
    collection = db[SCANS_COLLECTION]
    dnorm = normalize_domain_for_scan(request.domain)
    req = request.model_copy(update={"domain": dnorm})
    variants = variants_for_scan_domain(req.domain)

    active = await find_active_scan_for_domain(collection, variants)
    if active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "scan_in_progress",
                "message": "A scan is already running or queued for this domain.",
                "scan_id": active.get("scan_id"),
                "domain": active.get("domain"),
            },
        )

    cutoff = datetime.utcnow() - timedelta(days=max(1, settings.SCAN_REUSE_WINDOW_DAYS))
    reusable = await find_reusable_terminal_scan_for_domain(collection, variants, cutoff)
    if reusable:
        scan_id = reusable["scan_id"]
        await reset_scan_document_for_rerun(collection, scan_id, req, clear_batch_id=True)
        background_tasks.add_task(_run_scan_pipeline_gated, scan_id, req)
        logger.info("Scan %s reused (in-place rescan) for domain %s", scan_id, dnorm)
        return {
            "scan_id": scan_id,
            "domain": dnorm,
            "status": ScanStatus.PENDING.value,
            "message": "Scan initiated — poll GET /results/{domain} for progress.",
            "reused": True,
        }

    scan_id = uuid.uuid4().hex
    initial = ScanResult(
        scan_id=scan_id,
        domain=dnorm,
        status=ScanStatus.PENDING,
    )
    doc = initial.model_dump(mode="json")
    scan_opts: dict = {}
    if req.max_subdomains is not None:
        scan_opts["max_subdomains"] = req.max_subdomains
    if req.execution_time_limit_seconds is not None:
        scan_opts["execution_time_limit_seconds"] = req.execution_time_limit_seconds
    if scan_opts:
        doc["scan_options"] = scan_opts
    await collection.insert_one(doc)
    background_tasks.add_task(_run_scan_pipeline_gated, scan_id, req)

    logger.info("Scan %s queued for domain %s", scan_id, dnorm)
    return {
        "scan_id": scan_id,
        "domain": dnorm,
        "status": ScanStatus.PENDING.value,
        "message": "Scan initiated — poll GET /results/{domain} for progress.",
        "reused": False,
    }


@router.post("/scan/{scan_id}/cancel", tags=["Scanner"])
async def cancel_scan(scan_id: str):
    """Marks a scan as failed/cancelled. The pipeline checks the DB and will exit early."""
    db = get_database()
    collection = db[SCANS_COLLECTION]
    
    doc = await collection.find_one({"scan_id": scan_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if doc.get("status") in ("completed", "failed"):
        return {"status": "ok", "message": "Scan is already finished."}
        
    await collection.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": "failed",
            "error": "Cancelled by user via UI",
            "completed_at": datetime.utcnow()
        }}
    )
    
    await ws_manager.broadcast({
        "type": "status",
        "status": "failed",
        "message": "Cancelled by user via UI",
    }, scan_id)
    
    return {"status": "ok", "message": "Scan cancellation requested."}


@router.post("/scan/batch", tags=["Scanner"])
async def start_batch_scan(body: BatchScanRequest, background_tasks: BackgroundTasks):
    """Queue one scan job per domain; shares a global concurrency limit with single /scan."""
    raw = [str(d).strip().lower() for d in body.domains if d and str(d).strip()]
    seen: set[str] = set()
    uniq: List[str] = []
    for d in raw:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    if not uniq:
        raise HTTPException(status_code=400, detail="No valid domains in request")
    if len(uniq) > settings.MAX_BATCH_DOMAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many domains (max {settings.MAX_BATCH_DOMAINS} per batch)",
        )

    batch_id = uuid.uuid4().hex
    db = get_database()
    collection = db[SCANS_COLLECTION]
    jobs: List[dict] = []
    conflicts: List[dict] = []
    cutoff = datetime.utcnow() - timedelta(days=max(1, settings.SCAN_REUSE_WINDOW_DAYS))

    for domain in uniq:
        dnorm = normalize_domain_for_scan(domain)
        req = ScanRequest(
            domain=dnorm,
            include_subdomains=body.include_subdomains,
            ports=body.ports,
            merge_registered_inventory=body.merge_registered_inventory,
            max_subdomains=body.max_subdomains,
            execution_time_limit_seconds=body.execution_time_limit_seconds,
        )
        variants = variants_for_scan_domain(dnorm)

        active = await find_active_scan_for_domain(collection, variants)
        if active:
            conflicts.append(
                {
                    "domain": dnorm,
                    "error": "scan_in_progress",
                    "message": "A scan is already running or queued for this domain.",
                    "scan_id": active.get("scan_id"),
                }
            )
            continue

        reusable = await find_reusable_terminal_scan_for_domain(collection, variants, cutoff)
        if reusable:
            scan_id = reusable["scan_id"]
            await reset_scan_document_for_rerun(collection, scan_id, req, clear_batch_id=False)
            await collection.update_one(
                {"scan_id": scan_id},
                {"$set": {"batch_id": batch_id}},
            )
            background_tasks.add_task(_run_scan_pipeline_gated, scan_id, req)
            jobs.append({"scan_id": scan_id, "domain": dnorm, "reused": True})
            continue

        scan_id = uuid.uuid4().hex
        initial = ScanResult(
            scan_id=scan_id,
            batch_id=batch_id,
            domain=dnorm,
            status=ScanStatus.PENDING,
        )
        bdoc = initial.model_dump(mode="json")
        bopts: dict = {}
        if body.max_subdomains is not None:
            bopts["max_subdomains"] = body.max_subdomains
        if body.execution_time_limit_seconds is not None:
            bopts["execution_time_limit_seconds"] = body.execution_time_limit_seconds
        if bopts:
            bdoc["scan_options"] = bopts
        await collection.insert_one(bdoc)
        background_tasks.add_task(_run_scan_pipeline_gated, scan_id, req)
        jobs.append({"scan_id": scan_id, "domain": dnorm, "reused": False})

    logger.info(
        "Batch %s queued %d scan(s), %d conflict(s)",
        batch_id,
        len(jobs),
        len(conflicts),
    )
    return {
        "batch_id": batch_id,
        "queued": len(jobs),
        "jobs": jobs,
        "conflicts": conflicts,
        "message": "Scans queued — poll GET /results/{domain} or /scans/history?domain= for each target.",
    }


@router.get("/scans/history", tags=["Scanner"])
async def scans_history(domain: str, limit: int = 20, status_filter: Optional[str] = None):
    q: dict = {"domain": domain.strip().lower()}
    if status_filter in ("completed", "failed", "running", "pending"):
        q["status"] = status_filter
    lim = min(max(limit, 1), 100)
    db = get_database()
    cursor = (
        db[SCANS_COLLECTION]
        .find(q)
        .sort([("completed_at", -1), ("started_at", -1)])
        .limit(lim)
    )
    out: List[dict] = []
    async for doc in cursor:
        doc.pop("_id", None)
        qs = doc.get("quantum_score") or {}
        if not isinstance(qs, dict):
            qs = {}
        out.append(
            {
                "scan_id": doc.get("scan_id"),
                "domain": doc.get("domain"),
                "batch_id": doc.get("batch_id"),
                "status": doc.get("status"),
                "started_at": doc.get("started_at"),
                "completed_at": doc.get("completed_at"),
                "quantum_score": qs.get("score"),
                "risk_level": qs.get("risk_level"),
            }
        )
    return {"domain": domain.strip().lower(), "count": len(out), "scans": out}


@router.get("/scans/recent", tags=["Scanner"])
async def scans_recent(limit: int = 80, status_filter: Optional[str] = None):
    """Newest scan jobs first — avoids N+1 polling per domain on the Inventory Runs page."""
    def _parse_dt(v):
        if v is None:
            return None
        if hasattr(v, "isoformat"):
            return v
        s = str(v).strip()
        if not s:
            return None
        try:
            # tolerate ISO strings (optionally with trailing Z)
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

    lim = min(max(limit, 1), 200)
    q: dict = {}
    if status_filter in ("completed", "failed", "running", "pending"):
        q["status"] = status_filter
    db = get_database()
    cursor = (
        db[SCANS_COLLECTION]
        .find(q)
        .sort([("started_at", -1), ("completed_at", -1)])
        .limit(lim)
    )
    out: List[dict] = []
    async for doc in cursor:
        doc.pop("_id", None)
        qs = doc.get("quantum_score") or {}
        if not isinstance(qs, dict):
            qs = {}
        raw = doc.get("status")
        st = str(raw or "").strip().lower()
        if "." in st:
            st = st.split(".")[-1]
        err = doc.get("error")
        err_s = (str(err).strip() if err is not None else "")[:400]
        # Inconsistent writes: pipeline recorded error but status never flipped from running/pending
        if err_s and st in ("running", "pending"):
            st = "failed"

        # Stale jobs: user stopped mid-scan or worker died; flip to failed after timeout window.
        # Uses scan_options.execution_time_limit_seconds if present; otherwise Settings.SCAN_TIMEOUT.
        started_at = _parse_dt(doc.get("started_at"))
        completed_at = _parse_dt(doc.get("completed_at"))
        if completed_at is None and st in ("running", "pending") and started_at is not None:
            scan_opts = doc.get("scan_options") if isinstance(doc.get("scan_options"), dict) else {}
            opt_timeout = scan_opts.get("execution_time_limit_seconds")
            try:
                timeout_sec = int(opt_timeout) if opt_timeout is not None else int(settings.SCAN_TIMEOUT)
            except Exception:
                timeout_sec = int(settings.SCAN_TIMEOUT)
            # grace for queueing + tool cleanup
            grace = 90
            age = (datetime.utcnow() - started_at.replace(tzinfo=None)).total_seconds()
            if age > max(30, timeout_sec + grace):
                st = "failed"
                if not err_s:
                    err_s = "Scan stopped mid-run or timed out (stale running job)."
        out.append(
            {
                "scan_id": doc.get("scan_id"),
                "domain": doc.get("domain"),
                "batch_id": doc.get("batch_id"),
                "status": st or str(raw or "unknown"),
                "error": err_s or None,
                "started_at": doc.get("started_at"),
                "completed_at": doc.get("completed_at"),
                "quantum_score": qs.get("score"),
                "risk_level": qs.get("risk_level"),
            }
        )
    return {"count": len(out), "scans": out}


@router.get("/scans/diff", tags=["Scanner"])
async def scans_diff(
    domain: str,
    from_scan_id: str,
    to_scan_id: str,
):
    db = get_database()
    dom = domain.strip().lower()
    a = await db[SCANS_COLLECTION].find_one({"scan_id": from_scan_id, "domain": dom})
    b = await db[SCANS_COLLECTION].find_one({"scan_id": to_scan_id, "domain": dom})
    if not a or not b:
        raise HTTPException(
            status_code=404,
            detail="One or both scans not found for this domain",
        )
    ha, hb = _asset_host_set(a), _asset_host_set(b)
    ta, tb = _tls_by_host(a), _tls_by_host(b)
    tls_changed: List[dict] = []
    for h in ha & hb:
        if ta.get(h) != tb.get(h):
            tls_changed.append({"host": h, "before": ta.get(h), "after": tb.get(h)})
    qsa = (a.get("quantum_score") or {}) if isinstance(a.get("quantum_score"), dict) else {}
    qsb = (b.get("quantum_score") or {}) if isinstance(b.get("quantum_score"), dict) else {}
    return {
        "domain": dom,
        "from_scan_id": from_scan_id,
        "to_scan_id": to_scan_id,
        "new_subdomains": sorted(hb - ha),
        "removed_subdomains": sorted(ha - hb),
        "tls_endpoint_changes": tls_changed,
        "quantum_score": {"from": qsa.get("score"), "to": qsb.get("score")},
        "risk_level": {"from": qsa.get("risk_level"), "to": qsb.get("risk_level")},
    }


@router.get("/results/{domain}", tags=["Scanner"])
async def get_results(domain: str):
    db = get_database()
    
    # Priority 1: Find active running or pending scan
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain, "status": {"$in": ["running", "pending"]}},
        sort=[("started_at", -1)]
    )
    
    # Priority 2: Fall back to latest terminal scan (completed/failed with a valid timestamp)
    if not doc:
        doc = await db[SCANS_COLLECTION].find_one(
            {"domain": domain}, sort=[("completed_at", -1)]
        )
        
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )
    doc.pop("_id", None)
    return doc
