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



@router.get("/dashboard/summary", tags=["Dashboard"])
async def get_dashboard_summary():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=100)
    return _compute_dashboard_kpis_from_completed_scans(scans)


@router.get("/dashboard/policy-alignment", tags=["Dashboard"])
async def get_policy_alignment(_user: User = Depends(get_current_user)):
    """Phase 4: surface policy targets against the newest TLS inventory."""
    db = get_database()
    pol_doc = await db[ORG_POLICY_COLLECTION].find_one({"_id": "default"})
    merged = {**_DEFAULT_ORG_POLICY}
    if pol_doc:
        for k in merged:
            if k in pol_doc and pol_doc[k] is not None:
                merged[k] = pol_doc[k]

    scan = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    policy_public = {
        "min_tls_version": merged.get("min_tls_version"),
        "require_forward_secrecy": merged.get("require_forward_secrecy"),
        "pqc_readiness_target": merged.get("pqc_readiness_target") or "",
    }
    if not scan:
        return {
            "has_scan": False,
            "policy": policy_public,
            "alignment": None,
            "note": "No completed scan to compare.",
        }

    tls = scan.get("tls_results") or []
    alignment = summarize_tls_vs_policy(
        tls,
        str(merged.get("min_tls_version") or "1.2"),
        bool(merged.get("require_forward_secrecy")),
    )
    return {
        "has_scan": True,
        "scan_domain": scan.get("domain"),
        "policy": policy_public,
        "alignment": alignment,
    }


@router.get("/dashboard/migration-snapshot", tags=["Dashboard"])
async def get_migration_snapshot(_user: User = Depends(get_current_user)):
    """Phase 5: lightweight KPIs for the dashboard without loading full task lists."""
    db = get_database()
    open_tasks = await db[MIGRATION_TASKS_COLLECTION].count_documents(
        {"status": {"$in": ["open", "in_progress"]}}
    )
    pending_waivers = await db[WAIVERS_COLLECTION].count_documents({"status": "pending"})
    return {
        "open_tasks": open_tasks,
        "pending_waivers": pending_waivers,
    }


@router.get("/dashboard/executive-brief", tags=["Dashboard"])
async def get_executive_brief(_user: User = Depends(get_current_user)):
    """
    Single JSON for leadership demos and print/PDF workflows.
    Heuristic only — same qualifiers as dashboard summary and policy alignment.
    """
    db = get_database()
    now = datetime.now(timezone.utc)
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=100)

    kpis = _compute_dashboard_kpis_from_completed_scans(scans)
    open_tasks = await db[MIGRATION_TASKS_COLLECTION].count_documents(
        {"status": {"$in": ["open", "in_progress"]}}
    )
    pending_waivers = await db[WAIVERS_COLLECTION].count_documents({"status": "pending"})

    unique_hosts: set[str] = set()
    for s in scans:
        for a in s.get("assets", []) or []:
            h = (a.get("subdomain") or "").strip().lower()
            if h:
                unique_hosts.add(h)

    pol_doc = await db[ORG_POLICY_COLLECTION].find_one({"_id": "default"})
    merged = {**_DEFAULT_ORG_POLICY}
    if pol_doc:
        for k in merged:
            if k in pol_doc and pol_doc[k] is not None:
                merged[k] = pol_doc[k]

    policy_public = {
        "min_tls_version": merged.get("min_tls_version"),
        "require_forward_secrecy": merged.get("require_forward_secrecy"),
        "pqc_readiness_target": merged.get("pqc_readiness_target") or "",
    }

    latest = scans[0] if scans else None
    alignment = None
    if latest:
        tls = latest.get("tls_results") or []
        alignment = summarize_tls_vs_policy(
            tls,
            str(merged.get("min_tls_version") or "1.2"),
            bool(merged.get("require_forward_secrecy")),
        )

    domain_latest: dict[str, dict] = {}
    for s in scans:
        d = (s.get("domain") or "").strip().lower()
        if not d or d in domain_latest:
            continue
        qs = s.get("quantum_score") or {}
        if not isinstance(qs, dict):
            qs = {}
        domain_latest[d] = {
            "domain": s.get("domain"),
            "risk_level": qs.get("risk_level"),
            "score": qs.get("score"),
            "completed_at": s.get("completed_at"),
        }

    def _sort_key(row: dict) -> float:
        t = row.get("completed_at")
        if t is None:
            return 0.0
        if hasattr(t, "timestamp"):
            return float(t.timestamp())
        return 0.0

    domains_roll = sorted(domain_latest.values(), key=_sort_key, reverse=True)[:30]

    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "disclaimer": (
            "Heuristic portfolio snapshot for stakeholder discussion; "
            "not a compliance or audit attestation."
        ),
        "kpis": kpis,
        "portfolio": {
            "unique_hosts_observed": len(unique_hosts),
            "completed_scans_in_window": len(scans),
        },
        "migration": {
            "open_tasks": open_tasks,
            "pending_waivers": pending_waivers,
        },
        "policy": {
            "has_scan": latest is not None,
            "scan_domain": latest.get("domain") if latest else None,
            "targets": policy_public,
            "alignment": alignment,
        },
        "domains": domains_roll,
    }


@router.get("/dashboard/ops-snapshot", tags=["Dashboard"])
async def get_ops_snapshot(_admin: User = Depends(require_admin)):
    """Admin-only pipeline / datastore visibility for the operations console."""
    db = get_database()
    now = datetime.now(timezone.utc)
    db_ok = True
    db_err: Optional[str] = None
    try:
        await db.command("ping")
    except Exception as exc:
        db_ok = False
        db_err = str(exc)[:240]

    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    running = await db[SCANS_COLLECTION].count_documents({"status": "running"})
    pending = await db[SCANS_COLLECTION].count_documents({"status": "pending"})
    completed_24h = await db[SCANS_COLLECTION].count_documents(
        {"status": "completed", "completed_at": {"$gte": day_ago}}
    )
    failed_7d = await db[SCANS_COLLECTION].count_documents(
        {"status": "failed", "completed_at": {"$gte": week_ago}}
    )

    recent_failures: List[dict] = []
    async for doc in (
        db[SCANS_COLLECTION]
        .find({"status": "failed"})
        .sort("completed_at", -1)
        .limit(12)
    ):
        recent_failures.append(
            {
                "scan_id": doc.get("scan_id"),
                "domain": doc.get("domain"),
                "error": (doc.get("error") or "")[:280],
                "completed_at": doc.get("completed_at"),
            }
        )

    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app": {"name": settings.APP_NAME, "version": settings.APP_VERSION},
        "database": {"ok": db_ok, "error": db_err},
        "scans": {
            "running": running,
            "pending": pending,
            "completed_last_24h": completed_24h,
            "failed_last_7d": failed_7d,
        },
        "limits": {
            "max_concurrent_scans": settings.MAX_CONCURRENT_SCANS,
            "max_batch_domains": settings.MAX_BATCH_DOMAINS,
            "max_subdomains": settings.MAX_SUBDOMAINS,
            "scan_timeout_seconds": settings.SCAN_TIMEOUT,
        },
        "recent_failures": recent_failures,
    }
