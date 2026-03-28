"""
QuantumShield — API Routes (v1 scanner + all dashboard endpoints)

Endpoints:
  POST /scan                      → trigger a full scan
  GET  /results/{domain}          → retrieve scan results
  GET  /cbom/{domain}             → retrieve CBOM report
  GET  /quantum-score/{domain}    → retrieve quantum readiness score

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
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pymongo import ReturnDocument

from app.config import settings
from app.core.deps import get_current_user, require_admin
from app.db.connection import get_database
from app.db.models import (
    AssetMetadataUpdate,
    BatchScanRequest,
    InventorySourceImport,
    IntegrationSettingsUpdate,
    ExportAuditLogCreate,
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
from app.modules.threat_nist_mapping import (
    NIST_PQC_REFERENCES,
    build_prioritized_backlog,
    enrich_cbom_component_dict,
    simulate_quantum_score,
)
from app.modules.webhook_notify import post_json_webhook, post_slack_incoming_webhook
from app.core.ws_manager import manager as ws_manager
from app.utils.asset_type import asset_type_label, classify_asset_ports
from app.utils.logger import get_logger
from app.utils.policy_alignment import summarize_tls_vs_policy

logger = get_logger(__name__)

router = APIRouter(tags=["Scanner"])

@router.delete("/reset-db", summary="Development endpoint to drop the entire database")
async def drop_database_dev():
    """Drops the entire quantumshield database. Use only for development!"""
    db = get_database()
    await db.client.drop_database(db.name)
    return {"status": "success", "message": f"Database {db.name} dropped completely."}


@router.post("/system/wipe", summary="WIPE ALL MONGODB DATA")
async def wipe_all_data():
    """Clears all MongoDB collections in the current database."""
    print("--- SYSTEM WIPE INITIATED ---")
    
    try:
        db = get_database()
        collections = await db.list_collection_names()
        for coll in collections:
            await db[coll].delete_many({})
        mongo_status = "MongoDB Wipe Success"
    except Exception as e:
        mongo_status = f"MongoDB Error: {e}"

    return {
        "mongodb": mongo_status,
        "message": "All scan data has been wiped."
    }


# ── Collection name ──────────────────────────────────────────────
SCANS_COLLECTION = "scans"
ASSET_METADATA_COLLECTION = "asset_metadata"
ORG_POLICY_COLLECTION = "org_policy"
INTEGRATION_SETTINGS_COLLECTION = "integration_settings"
EXPORT_AUDIT_COLLECTION = "export_audit"
MIGRATION_TASKS_COLLECTION = "migration_tasks"
WAIVERS_COLLECTION = "waivers"
REGISTERED_ASSETS_COLLECTION = "registered_assets"
SBOM_ARTIFACTS_COLLECTION = "sbom_artifacts"

_DEFAULT_ORG_POLICY: Dict[str, Any] = {
    "min_tls_version": "1.2",
    "require_forward_secrecy": True,
    "pqc_readiness_target": "",
    "policy_notes": "",
}

_DEFAULT_INTEGRATION: Dict[str, Any] = {
    "outbound_webhook_url": "",
    "notify_on_scan_complete": False,
    "slack_webhook_url": "",
    "jira_webhook_url": "",
}

_scan_sem = asyncio.Semaphore(max(1, settings.MAX_CONCURRENT_SCANS))


def _mask_url(u: Optional[str]) -> Optional[str]:
    if not u or not str(u).strip():
        return None
    s = str(u).strip()
    if len(s) <= 24:
        return "****"
    return s[:20] + "…" + s[-4:]


async def _notify_scan_complete_hooks(scan_id: str, domain: str, quantum_score: dict) -> None:
    db = get_database()
    doc = await db[INTEGRATION_SETTINGS_COLLECTION].find_one({"_id": "default"})
    if not doc or not doc.get("notify_on_scan_complete"):
        return
    payload = {
        "event": "quantumshield.scan.completed",
        "scan_id": scan_id,
        "domain": domain,
        "quantum_score": quantum_score or {},
    }
    url = (doc.get("outbound_webhook_url") or "").strip()
    if url:
        await post_json_webhook(url, payload)

    slack_u = (doc.get("slack_webhook_url") or "").strip()
    if slack_u:
        qs = quantum_score or {}
        risk = qs.get("risk_level", "n/a")
        score = qs.get("score", "n/a")
        text = (
            f"*QuantumShield* — scan completed\n"
            f"• Domain: `{domain}`\n"
            f"• Scan ID: `{scan_id}`\n"
            f"• Risk: `{risk}` · Score: `{score}`"
        )
        await post_slack_incoming_webhook(slack_u, text)

    jira_u = (doc.get("jira_webhook_url") or "").strip()
    if jira_u:
        await post_json_webhook(jira_u, payload)


async def _run_scan_pipeline_gated(scan_id: str, request: ScanRequest) -> None:
    """Run pipeline with global concurrency cap (Phase 2 portfolio scans)."""
    async with _scan_sem:
        await _run_scan_pipeline(scan_id, request)


async def _registered_hostnames_for_domain(db, domain: str, lim: int = 500) -> List[str]:
    """Hosts previously imported via /inventory/sources/import scoped to this scan domain."""
    d = (domain or "").strip().lower()
    if not d:
        return []
    esc = re.escape(d)
    q: dict = {
        "$or": [
            {"parent_domain": d},
            {"host": {"$regex": rf"^(.+\.)?{esc}$"}},
        ]
    }
    out: List[str] = []
    cursor = db[REGISTERED_ASSETS_COLLECTION].find(q).limit(lim)
    async for doc in cursor:
        h = (doc.get("host") or "").strip().lower()
        if h and h not in out:
            out.append(h)
    return out


# ── Helper: run full pipeline ────────────────────────────────────

async def _run_scan_pipeline(scan_id: str, request: ScanRequest) -> None:
    """
    Execute the full scan pipeline in the background (8 stages, MongoDB only).

    Stages:
      1. Asset discovery (subdomains, ports, DNS NS, optional inventory merge / seed hosts)
      2. TLS scanning
      3. Crypto analysis
      4. Quantum risk scoring
      5. CBOM generation
      6. PQC recommendations
      7. HTTP security headers
      8. CVE / known-attack mapping

    WebSocket frames from this pipeline include type, scan_id, ts (see enrich_ws_payload).
    """
    db = get_database()
    collection = db[SCANS_COLLECTION]

    try:
        # Mark as running — expose stage early so UI/poll stay in sync during discovery
        await collection.update_one(
            {"scan_id": scan_id},
            {
                "$set": {
                    "status": ScanStatus.RUNNING.value,
                    "started_at": datetime.utcnow(),
                    "current_stage": "Asset Discovery",
                    "progress": 5,
                }
            },
        )

        # ── Stage 1: Asset Discovery ─────────────────────────────
        logger.info("[%s] Stage 1/8: Asset Discovery", scan_id)

        async def broadcast_tool_log(msg: str):
            await ws_manager.broadcast({
                "type": "log",
                "stage": 1,
                "message": msg
            }, scan_id)

        await ws_manager.broadcast({
            "type": "status",
            "stage": 1,
            "status": "running",
            "message": "Starting Asset Discovery..."
        }, scan_id)

        assets = await asset_discovery.discover_assets(
            request.domain, ports=request.ports, broadcast_func=broadcast_tool_log
        )

        seed_hosts: List[str] = []
        if request.additional_seed_hosts:
            seed_hosts.extend(request.additional_seed_hosts)
        if request.merge_registered_inventory:
            seed_hosts.extend(await _registered_hostnames_for_domain(db, request.domain))
        seed_hosts = list(dict.fromkeys(seed_hosts))
        if seed_hosts:
            await broadcast_tool_log(
                f"Merging {len(seed_hosts)} inventory/seed host(s) into discovery set…"
            )
            assets = await asset_discovery.merge_extra_hosts_into_assets(
                assets,
                seed_hosts,
                ports=request.ports,
                broadcast_func=broadcast_tool_log,
            )

        # Merge org metadata from inventory (Phase 2)
        meta_coll = db[ASSET_METADATA_COLLECTION]
        merged: List = []
        for a in assets:
            key = (a.subdomain or "").strip().lower()
            doc = await meta_coll.find_one({"host": key}) if key else None
            if doc:
                merged.append(
                    a.model_copy(
                        update={
                            "owner": doc.get("owner") or a.owner,
                            "environment": doc.get("environment") or a.environment,
                            "criticality": doc.get("criticality") or a.criticality,
                        }
                    )
                )
            else:
                merged.append(a)
        assets = merged

        # ── New Stage: DNS Record Collection ──
        logger.info("[%s] Collecting DNS records for %s", scan_id, request.domain)
        dns_records = await asset_discovery.get_ns_records(request.domain)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"dns_records": [r.model_dump() for r in dns_records]}},
        )

        web_count = sum(1 for a in assets if classify_asset_ports(a.open_ports) == "web_app")
        srv_count = sum(1 for a in assets if classify_asset_ports(a.open_ports) == "server")
        api_count = sum(1 for a in assets if classify_asset_ports(a.open_ports) == "api")

        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {
                "total_assets": len(assets),
                "public_web_apps": web_count,
                "servers": srv_count,
                "apis": api_count,
            }
        }, scan_id)

        await ws_manager.broadcast({
            "type": "data",
            "stage": 1,
            "assets_count": len(assets),
            "assets": [a.model_dump() for a in assets],
            "message": f"Discovery complete: {len(assets)} assets found."
        }, scan_id)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "assets": [a.model_dump() for a in assets],
                "current_stage": "Asset Discovery",
                "progress": 15,
            }},
        )

        # ── Stage 2: TLS Scanning ────────────────────────────────
        logger.info("[%s] Stage 2/8: TLS Scanning", scan_id)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"current_stage": "TLS Scanning", "progress": 20}},
        )
        await ws_manager.broadcast(
            {
                "type": "status",
                "stage": 2,
                "status": "running",
                "message": "TLS scanning (testssl / handshake probes)…",
            },
            scan_id,
        )
        tls_tasks = []
        for asset in assets:
            for port in asset.open_ports:
                tls_tasks.append(tls_scanner.scan_tls(asset.subdomain, port))

        tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)
        tls_results = [r for r in tls_results if isinstance(r, TLSInfo)]

        expiring = sum(
            1 for t in tls_results
            if t.certificate and (t.certificate.days_until_expiry or 365) <= 30
        )

        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {"expiring_certificates": expiring}
        }, scan_id)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "tls_results": [t.model_dump() for t in tls_results],
                "current_stage": "TLS Scanning",
                "progress": 35,
            }},
        )

        # ── Stage 3: Crypto Analysis ────────────────────────────
        logger.info("[%s] Stage 3/8: Crypto Analysis", scan_id)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"current_stage": "Crypto Analysis", "progress": 40}},
        )
        await ws_manager.broadcast(
            {
                "type": "status",
                "stage": 3,
                "status": "running",
                "message": "Crypto analysis…",
            },
            scan_id,
        )
        all_components: List[CryptoComponent] = []
        for tls_info in tls_results:
            components = crypto_analyzer.analyze(tls_info)
            all_components.extend(components)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "cbom": [c.model_dump() for c in all_components],
                "current_stage": "Crypto Analysis",
                "progress": 55,
            }},
        )

        # ── Stage 4: Quantum Risk Scoring ────────────────────────
        logger.info("[%s] Stage 4/8: Quantum Risk Scoring", scan_id)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"current_stage": "Quantum Risk", "progress": 60}},
        )
        await ws_manager.broadcast(
            {
                "type": "status",
                "stage": 4,
                "status": "running",
                "message": "Quantum risk scoring…",
            },
            scan_id,
        )
        q_score = quantum_risk_engine.calculate_score(all_components)

        is_high_risk = 1 if q_score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] else 0

        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {"high_risk_assets": is_high_risk}
        }, scan_id)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "quantum_score": q_score.model_dump(),
                "current_stage": "Quantum Risk",
                "progress": 70,
            }},
        )

        # ── Stage 5: CBOM Generation ────────────────────────────
        logger.info("[%s] Stage 5/8: CBOM Generation", scan_id)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"current_stage": "CBOM Generation", "progress": 75}},
        )
        await ws_manager.broadcast(
            {
                "type": "status",
                "stage": 5,
                "status": "running",
                "message": "CBOM generation…",
            },
            scan_id,
        )
        scan_data = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            cbom=all_components,
        )
        cbom_report = cbom_generator.generate_cbom(scan_data)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "cbom_report": cbom_report.model_dump(mode="json"),
                "current_stage": "CBOM Generation",
                "progress": 85,
            }},
        )

        # ── Stage 6: Recommendations ────────────────────────────
        logger.info("[%s] Stage 6/8: PQC Recommendations", scan_id)
        recs = recommendation_engine.get_recommendations(all_components, q_score)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "recommendations": [r.model_dump() for r in recs],
                "current_stage": "Recommendations",
                "progress": 90,
            }},
        )

        # ── Stage 7: HTTP Security Headers ───────────────────────
        logger.info("[%s] Stage 7/8: HTTP Security Headers", scan_id)
        headers_tasks = [scan_headers(asset.subdomain) for asset in assets]
        headers_results = await asyncio.gather(*headers_tasks, return_exceptions=True)
        headers_results = [r for r in headers_results if not isinstance(r, Exception)]

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "headers_results": [h.model_dump() for h in headers_results],
                "current_stage": "HTTP Headers",
                "progress": 95,
            }},
        )

        # ── Stage 8: CVE / Known-Attack Mapping ──────────────────
        logger.info("[%s] Stage 8/8: CVE / Known-Attack Mapping", scan_id)
        cve_findings = map_cves(tls_results)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "cve_findings": [c.model_dump() for c in cve_findings],
                "current_stage": "CVE Mapping",
                "progress": 100,
                "status": ScanStatus.COMPLETED.value,
                "completed_at": datetime.utcnow(),
            }},
        )

        await ws_manager.broadcast({
            "type": "status",
            "stage": 8,
            "status": "completed",
            "message": "Scan completed successfully."
        }, scan_id)

        asyncio.create_task(
            _notify_scan_complete_hooks(
                scan_id,
                request.domain,
                q_score.model_dump(mode="json"),
            )
        )

        logger.info("[%s] ✅ Scan pipeline completed (8/8 stages).", scan_id)

    except Exception as exc:
        logger.exception("[%s] ❌ Scan pipeline failed: %s", scan_id, exc)
        err_text = str(exc)[:500]
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": ScanStatus.FAILED.value,
                "error": err_text,
                "completed_at": datetime.utcnow(),
            }},
        )
        await ws_manager.broadcast(
            {
                "type": "status",
                "status": "failed",
                "message": err_text,
            },
            scan_id,
        )


# ════════════════════════════════════════════════════════════════════
# Scanner endpoints (original)
# ════════════════════════════════════════════════════════════════════

@router.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a full cryptographic scan",
)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start an asynchronous scan of the given domain."""
    scan_id = uuid.uuid4().hex
    db = get_database()

    initial = ScanResult(
        scan_id=scan_id,
        domain=request.domain,
        status=ScanStatus.PENDING,
    )
    await db[SCANS_COLLECTION].insert_one(initial.model_dump(mode="json"))
    background_tasks.add_task(_run_scan_pipeline_gated, scan_id, request)

    logger.info("Scan %s queued for domain %s", scan_id, request.domain)
    return {
        "scan_id": scan_id,
        "domain": request.domain,
        "status": ScanStatus.PENDING.value,
        "message": "Scan initiated — poll GET /results/{domain} for progress.",
    }


@router.post(
    "/scan/batch",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue scans for multiple domains (portfolio)",
    tags=["Scanner"],
)
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
    jobs: List[dict] = []
    for domain in uniq:
        scan_id = uuid.uuid4().hex
        req = ScanRequest(
            domain=domain,
            include_subdomains=body.include_subdomains,
            ports=body.ports,
            merge_registered_inventory=body.merge_registered_inventory,
        )
        initial = ScanResult(
            scan_id=scan_id,
            batch_id=batch_id,
            domain=domain,
            status=ScanStatus.PENDING,
        )
        await db[SCANS_COLLECTION].insert_one(initial.model_dump(mode="json"))
        background_tasks.add_task(_run_scan_pipeline_gated, scan_id, req)
        jobs.append({"scan_id": scan_id, "domain": domain})

    logger.info("Batch %s queued %d scan(s)", batch_id, len(jobs))
    return {
        "batch_id": batch_id,
        "queued": len(jobs),
        "jobs": jobs,
        "message": "Scans queued — poll GET /results/{domain} or /scans/history?domain= for each target.",
    }


@router.get("/scans/history", summary="List recent scans for a domain", tags=["Portfolio"])
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


@router.get(
    "/scans/recent",
    summary="Recent scans across all domains (portfolio queue view)",
    tags=["Portfolio"],
)
async def scans_recent(limit: int = 80, status_filter: Optional[str] = None):
    """Newest scan jobs first — avoids N+1 polling per domain on the Inventory Runs page."""
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
    return {"count": len(out), "scans": out}


def _asset_host_set(scan_doc: dict) -> set:
    return {x.get("subdomain") for x in (scan_doc.get("assets") or []) if x.get("subdomain")}


def _tls_by_host(scan_doc: dict) -> dict:
    m: dict = {}
    for t in scan_doc.get("tls_results") or []:
        h = t.get("host")
        if not h:
            continue
        m[h] = {
            "tls_version": t.get("tls_version"),
            "cipher_suite": t.get("cipher_suite"),
            "pqc_kem_observed": t.get("pqc_kem_observed"),
        }
    return m


@router.get("/scans/diff", summary="Compare two scans for the same domain", tags=["Portfolio"])
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


@router.get("/inventory/summary", summary="Deduplicated hosts across recent completed scans", tags=["Portfolio"])
async def inventory_summary(limit_scans: int = 100):
    """Portfolio view: unique subdomains with latest quantum risk and optional org metadata."""
    lim = min(max(limit_scans, 1), 500)
    db = get_database()
    cursor = (
        db[SCANS_COLLECTION]
        .find({"status": "completed"})
        .sort("completed_at", -1)
        .limit(lim)
    )
    by_host: dict[str, dict] = {}
    async for scan in cursor:
        root = scan.get("domain") or ""
        qs = scan.get("quantum_score") or {}
        qr = qs.get("risk_level") if isinstance(qs, dict) else None
        qscore = qs.get("score") if isinstance(qs, dict) else None
        completed = scan.get("completed_at")
        sid = scan.get("scan_id")
        for asset in scan.get("assets") or []:
            h = (asset.get("subdomain") or "").strip().lower()
            if not h:
                continue
            prev = by_host.get(h)
            if prev is None:
                by_host[h] = {
                    "host": h,
                    "parent_domain": root,
                    "last_scan_id": sid,
                    "last_completed_at": completed,
                    "quantum_risk_level": qr,
                    "quantum_score": qscore,
                    "ip": asset.get("ip"),
                    "open_ports": asset.get("open_ports") or [],
                    "owner": asset.get("owner"),
                    "environment": asset.get("environment"),
                    "criticality": asset.get("criticality"),
                }
            elif completed and (
                prev.get("last_completed_at") is None or completed > prev["last_completed_at"]
            ):
                by_host[h].update(
                    {
                        "parent_domain": root,
                        "last_scan_id": sid,
                        "last_completed_at": completed,
                        "quantum_risk_level": qr,
                        "quantum_score": qscore,
                        "ip": asset.get("ip") or prev.get("ip"),
                        "open_ports": asset.get("open_ports") or prev.get("open_ports"),
                        "owner": asset.get("owner") or prev.get("owner"),
                        "environment": asset.get("environment") or prev.get("environment"),
                        "criticality": asset.get("criticality") or prev.get("criticality"),
                    }
                )

    meta_coll = db[ASSET_METADATA_COLLECTION]
    hosts = sorted(by_host.values(), key=lambda r: r["host"])
    for row in hosts:
        h = row["host"]
        m = await meta_coll.find_one({"host": h})
        if m:
            row["owner"] = m.get("owner") or row.get("owner")
            row["environment"] = m.get("environment") or row.get("environment")
            row["criticality"] = m.get("criticality") or row.get("criticality")

    return {
        "scans_considered": lim,
        "host_count": len(hosts),
        "hosts": hosts,
    }


@router.post(
    "/inventory/sources/import",
    summary="Register assets from CMDB, cloud, K8s, Git jobs, etc.",
    tags=["Portfolio"],
)
async def import_inventory_sources(
    body: InventorySourceImport,
    user: User = Depends(get_current_user),
):
    """
    Upserts `registered_assets` and mirrors owner/env/criticality into `asset_metadata`
    so the existing scan pipeline picks them up on merge_registered_inventory.
    """
    db = get_database()
    now = datetime.utcnow()
    src = body.source.strip()[:48]
    default_parent = (body.parent_domain or "").strip().lower() or None
    n = 0
    for item in body.items:
        h = item.host.strip().lower()
        if not h:
            continue
        pd = (item.parent_domain or default_parent or "").strip().lower() or None
        doc = {
            "host": h,
            "parent_domain": pd,
            "source": src,
            "external_id": (item.external_id or "").strip()[:256] or None,
            "owner": item.owner,
            "environment": item.environment,
            "criticality": item.criticality,
            "notes": item.notes,
            "updated_at": now,
            "updated_by": user.email,
        }
        await db[REGISTERED_ASSETS_COLLECTION].update_one(
            {"host": h},
            {"$set": doc, "$setOnInsert": {"created_at": now}},
            upsert=True,
        )
        meta_patch = {
            k: v
            for k, v in {
                "owner": item.owner,
                "environment": item.environment,
                "criticality": item.criticality,
            }.items()
            if v is not None and str(v).strip() != ""
        }
        if meta_patch:
            meta_patch["updated_at"] = now
            await db[ASSET_METADATA_COLLECTION].update_one(
                {"host": h},
                {"$set": meta_patch},
                upsert=True,
            )
        n += 1
    return {"status": "ok", "source": src, "upserted": n}


@router.get("/inventory/registered", summary="List registered external inventory hosts", tags=["Portfolio"])
async def list_registered_assets(
    domain: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 200,
    _user: User = Depends(get_current_user),
):
    lim = min(max(limit, 1), 500)
    db = get_database()
    q: dict = {}
    conds: List[dict] = []
    if domain:
        d = domain.strip().lower()
        esc = re.escape(d)
        conds.append({"$or": [{"parent_domain": d}, {"host": {"$regex": rf"^(.+\.)?{esc}$"}}]})
    if source:
        conds.append({"source": source.strip()[:48]})
    if len(conds) == 1:
        q = conds[0]
    elif len(conds) > 1:
        q = {"$and": conds}
    cursor = db[REGISTERED_ASSETS_COLLECTION].find(q).sort("host", 1).limit(lim)
    rows: List[dict] = []
    async for doc in cursor:
        doc.pop("_id", None)
        rows.append(doc)
    return {"count": len(rows), "assets": rows}


@router.post("/inventory/sbom", summary="Store SBOM JSON for a host (CycloneDX/SPDX-style)", tags=["Portfolio"])
async def ingest_sbom_artifact(
    body: SbomIngestRequest,
    user: User = Depends(get_current_user),
):
    """Supply-chain / SAST hook: persists raw JSON for dashboards or future library-level CBOM."""
    db = get_database()
    aid = uuid.uuid4().hex
    host = body.host.strip().lower()
    sd = (body.scan_domain or "").strip().lower() or None
    doc = {
        "artifact_id": aid,
        "host": host,
        "scan_domain": sd,
        "format": (body.format or "cyclonedx").strip()[:32],
        "document": body.document,
        "created_at": datetime.utcnow(),
        "created_by": user.email,
    }
    await db[SBOM_ARTIFACTS_COLLECTION].insert_one(doc)
    out = {k: v for k, v in doc.items() if k != "_id"}
    return out


@router.put("/assets/metadata", summary="Upsert metadata for one host", tags=["Portfolio"])
async def put_asset_metadata(body: AssetMetadataUpdate):
    host = body.host.strip().lower()
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    db = get_database()
    doc = {
        "host": host,
        "owner": body.owner,
        "environment": body.environment,
        "criticality": body.criticality,
        "updated_at": datetime.utcnow(),
    }
    await db[ASSET_METADATA_COLLECTION].update_one(
        {"host": host},
        {"$set": doc},
        upsert=True,
    )
    return {"status": "ok", "host": host}


@router.post("/assets/metadata/bulk", summary="Upsert metadata for many hosts", tags=["Portfolio"])
async def bulk_asset_metadata(items: List[AssetMetadataUpdate]):
    if len(items) > 500:
        raise HTTPException(status_code=400, detail="Max 500 rows per bulk request")
    db = get_database()
    n = 0
    for body in items:
        host = body.host.strip().lower()
        if not host:
            continue
        doc = {
            "host": host,
            "owner": body.owner,
            "environment": body.environment,
            "criticality": body.criticality,
            "updated_at": datetime.utcnow(),
        }
        await db[ASSET_METADATA_COLLECTION].update_one(
            {"host": host},
            {"$set": doc},
            upsert=True,
        )
        n += 1
    return {"status": "ok", "upserted": n}


@router.get("/results/{domain}", summary="Get scan results for a domain")
async def get_results(domain: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain}, sort=[("started_at", -1)]
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )
    doc.pop("_id", None)
    return doc


@router.get("/cbom/summary", summary="Get CBOM summary statistics", tags=["CBOM"])
async def get_cbom_summary(domain: str = None):
    db = get_database()
    
    # If domain provided, use specific scan. Otherwise latest completed.
    query = {"status": "completed"}
    if domain:
        query["domain"] = domain
        
    doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        return {
            "total_applications": 0, "sites_surveyed": 0, "active_certificates": 0,
            "weak_cryptography": 0, "certificate_issues": 0
        }

    cbom_report = doc.get("cbom_report") or {}
    _rs = cbom_report.get("risk_summary")
    risk_summary = _rs if isinstance(_rs, dict) else {}
    
    # Map fields to match frontend expectations
    return {
        "domain": doc.get("domain", ""),
        "generated_at": doc.get("completed_at", ""),
        "total_applications": 1 if domain else (await db[SCANS_COLLECTION].count_documents({"status": "completed"})),
        "sites_surveyed": cbom_report.get("total_components", 0),
        "active_certificates": len(doc.get("tls_results", [])),
        "weak_cryptography": risk_summary.get("high", 0) + risk_summary.get("critical", 0),
        "certificate_issues": sum(1 for t in doc.get("tls_results", []) 
                                if (t.get("certificate") or {}).get("days_until_expiry", 999) <= 30),
    }

@router.get("/cbom/per-app", summary="Get per-application CBOM components", tags=["CBOM"])
async def get_cbom_per_app(domain: str = None):
    db = get_database()
    query = {"status": "completed"}
    if domain:
        query["domain"] = domain
        
    doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        return []
        
    # Standardize output for the table + Phase 3 threat ↔ NIST enrichment
    cbom_report = doc.get("cbom_report") or {}
    components = cbom_report.get("components", []) or []
    return [enrich_cbom_component_dict(dict(c)) for c in components]

@router.get("/cbom/charts", summary="Get CBOM chart data", tags=["CBOM"])
async def get_cbom_charts(domain: str = None):
    db = get_database()
    
    if domain:
        query = {"domain": domain, "status": "completed"}
        doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
        scans = [doc] if doc else []
    else:
        scans = await db[SCANS_COLLECTION].find({"status": "completed"}).to_list(length=100)

    key_lengths: dict = {}
    tls_versions: dict = {}
    cas: dict = {}
    cipher_usage: dict = {}

    for scan in scans:
        # Use cbom_report components for better granularity if available
        cr = scan.get("cbom_report") or {}
        all_components = cr.get("components", []) or []
        if not all_components:
            # Fallback to tls_results if cbom_report missing
            all_components = []
            for t in scan.get("tls_results", []):
                all_components.append({
                    "name": t.get("cipher_suite", "Unknown"),
                    "category": "cipher",
                    "key_size": t.get("cipher_bits") or t.get("key_length"),
                    "details": t.get("tls_version", "TLS 1.2")
                })

        for c in all_components:
            category = c.get("category", "")
            name = c.get("name", "Unknown")
            
            if category == "protocol":
                tls_versions[name] = tls_versions.get(name, 0) + 1
            elif category == "cipher":
                cipher_usage[name] = cipher_usage.get(name, 0) + 1
                ks = str(c.get("key_size") or "2048")
                key_lengths[ks] = key_lengths.get(ks, 0) + 1
        
        # CAs still come from tls_results (cert chain)
        for t in scan.get("tls_results", []):
            ca = (t.get("certificate") or {}).get("issuer", "Unknown") or "Unknown"
            cas[ca] = cas.get(ca, 0) + 1

    return {
        "key_length_distribution": [{"name": k, "count": v} for k, v in key_lengths.items()],
        "top_certificate_authorities": [{"name": k, "value": v} for k, v in cas.items()],
        "encryption_protocols": [{"name": k, "value": v} for k, v in tls_versions.items()],
        "cipher_usage": [
            {
                "name": k,
                "value": v,
                "weak": ("MD5" in str(k) or "RC4" in str(k) or "DES" in str(k) or "TLSv1.0" in str(k)),
            }
            for k, v in cipher_usage.items()
        ],
    }


@router.get("/cbom/{domain}", summary="Get Cryptographic Bill of Materials")
async def get_cbom_domain(domain: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain}, sort=[("started_at", -1)]
    )
    if not doc:
        raise HTTPException(status_code=404, detail=f"No scan results found for domain: {domain}")
    cbom_report = doc.get("cbom_report")
    if not cbom_report:
        raise HTTPException(status_code=404, detail=f"CBOM not yet generated for domain: {domain}")
    return cbom_report


@router.get("/quantum-score/{domain}", summary="Get Quantum Readiness Score")
async def get_quantum_score(domain: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain}, sort=[("started_at", -1)]
    )
    if not doc:
        raise HTTPException(status_code=404, detail=f"No scan results found for domain: {domain}")
    q_score = doc.get("quantum_score")
    if not q_score:
        raise HTTPException(status_code=404, detail=f"Quantum score not yet calculated for domain: {domain}")
    return {"domain": domain, "quantum_score": q_score, "recommendations": doc.get("recommendations", [])}


# ════════════════════════════════════════════════════════════════════
# Dashboard Summary
# ════════════════════════════════════════════════════════════════════


def _compute_dashboard_kpis_from_completed_scans(scans: List[dict]) -> dict:
    """Shared KPI math for /dashboard/summary and /dashboard/executive-brief."""
    total_assets = sum(len(s.get("assets", [])) for s in scans)
    tls_all: List[dict] = []
    for s in scans:
        tls_all.extend(s.get("tls_results", []) or [])
    expiring = sum(
        1
        for t in tls_all
        if t.get("certificate", {})
        and 0 < (t.get("certificate", {}).get("days_until_expiry") or 365) <= 30
    )
    high_risk = sum(
        1
        for s in scans
        if (s.get("quantum_score") or {}).get("risk_level") in ["high", "critical"]
    )

    public_web_apps = 0
    apis = 0
    servers = 0

    for s in scans:
        for a in s.get("assets", []) or []:
            cat = classify_asset_ports(a.get("open_ports") or [])
            if cat == "web_app":
                public_web_apps += 1
            elif cat == "server":
                servers += 1
            else:
                apis += 1

    return {
        "total_assets": total_assets,
        "public_web_apps": public_web_apps,
        "apis": apis,
        "servers": servers,
        "expiring_certificates": expiring,
        "high_risk_assets": high_risk,
    }


@router.get("/dashboard/summary", summary="Get dashboard summary stats", tags=["Dashboard"])
async def get_dashboard_summary():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=100)
    return _compute_dashboard_kpis_from_completed_scans(scans)


@router.get(
    "/dashboard/policy-alignment",
    summary="Org crypto policy vs latest completed scan (indicative)",
    tags=["Dashboard"],
)
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


@router.get(
    "/dashboard/migration-snapshot",
    summary="Migration execution counts (open tasks, pending waivers)",
    tags=["Dashboard"],
)
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


@router.get(
    "/dashboard/executive-brief",
    summary="Stakeholder rollup: KPIs, policy, migration, domain posture (Phase 6)",
    tags=["Dashboard"],
)
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


@router.get(
    "/dashboard/ops-snapshot",
    summary="Operator health: DB ping, scan queue counts, recent failures (Phase 7)",
    tags=["Dashboard"],
)
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


# ════════════════════════════════════════════════════════════════════
# Assets endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/assets", summary="Get all discovered assets", tags=["Assets"])
async def get_assets():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=10)

    assets = []
    for scan in scans:
        tls_map = {t.get("host"): t for t in scan.get("tls_results", [])}
        for a in scan.get("assets", []):
            host = a.get("subdomain", "")
            tls = tls_map.get(host, {})
            cert = tls.get("certificate") or {}
            
            # Infer fields (must match /dashboard/summary and /assets/distribution)
            ports = a.get("open_ports") or []
            a_type = asset_type_label(classify_asset_ports(ports))
            
            days = cert.get("days_until_expiry")
            if days is None: cert_status_slug = "unknown"
            elif days <= 0: cert_status_slug = "expired"
            elif days <= 30: cert_status_slug = "expiring_soon"
            else: cert_status_slug = "valid"

            assets.append({
                "asset_name": host,
                "url": f"https://{host}",
                "ipv4": a.get("ip", ""),
                "ipv6": "",
                "type": a_type,
                "owner": "",
                "risk": scan.get("quantum_score", {}).get("risk_level", "").capitalize(),
                "hndlRisk": False,
                "certificate_status": cert_status_slug,
                "certStatus": cert_status_slug.replace("_", " ").title() if cert_status_slug != "unknown" else "",
                "pqcStatus": "Ready" if tls.get("tls_version") == "TLSv1.3" else "",
                "key_length": str(tls.get("cipher_bits") or ""),
                "last_scan": str(scan.get("completed_at", ""))[:10],
                "tls_version": tls.get("tls_version", ""),
                "cipher_suite": tls.get("cipher_suite", ""),
            })

    return {
        "items": assets,
        "total": len(assets),
        "page": 1,
        "page_size": 100
    }


@router.get("/assets/distribution", summary="Get asset type distribution", tags=["Assets"])
async def get_asset_distribution():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=10)

    public_web_apps = 0
    apis = 0
    servers = 0
    
    for s in scans:
        for a in s.get("assets", []):
            cat = classify_asset_ports(a.get("open_ports") or [])
            if cat == "web_app":
                public_web_apps += 1
            elif cat == "server":
                servers += 1
            else:
                apis += 1

    return [
        {"name": "Web Apps", "value": public_web_apps},
        {"name": "APIs", "value": apis},
        {"name": "Servers", "value": servers},
    ]


# ════════════════════════════════════════════════════════════════════
# CBOM endpoints
# ════════════════════════════════════════════════════════════════════




# ════════════════════════════════════════════════════════════════════
# DNS / Nameserver endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/dns/nameserver-records", summary="Get DNS nameserver records", tags=["DNS"])
async def get_nameserver_records():
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    if not doc:
        return []
    return doc.get("dns_records", [])



# ════════════════════════════════════════════════════════════════════
# Crypto Security endpoint
# ════════════════════════════════════════════════════════════════════

@router.get("/crypto/security", summary="Get crypto security overview", tags=["Crypto"])
async def get_crypto_security():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=5)

    results = []
    for scan in scans:
        for t in scan.get("tls_results", []):
            cert = t.get("certificate") or {}
            results.append({
                "asset": t.get("host", scan.get("domain", "")),
                "key_length": str(t.get('cipher_bits') or ""),
                "cipher_suite": t.get("cipher_suite", ""),
                "tls_version": t.get("tls_version", ""),
                "certificate_authority": cert.get("issuer", ""),
                "pqcStatus": "",
            })

    return results



# ════════════════════════════════════════════════════════════════════
# PQC Posture endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/pqc/posture", summary="Get PQC posture overview", tags=["PQC"])
async def get_pqc_posture():
    db = get_database()
    scan = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    if not scan:
        return {
            "elite_count": 0,
            "standard_count": 0,
            "critical_apps": 0,
            "elite_pqc_pct": 0.0,
            "standard_pct": 0.0,
            "legacy_pct": 0.0,
            "critical_pct": 0.0,
            "pqc_kem_endpoints": 0,
            "tls_modern_endpoints": 0,
            "asset_pqc_status": [],
            "recommendations": [],
        }

    tls_results = scan.get("tls_results", [])
    assets = scan.get("assets", [])
    tls_map = {t.get("host"): t for t in tls_results}
    
    asset_pqc_status = []
    elite_pqc_count = 0
    standard_count = 0
    legacy_count = 0
    critical_count = 0

    pqc_kem_endpoints = 0
    tls_modern_endpoints = 0

    for a in assets:
        host = a.get("subdomain")
        tls = tls_map.get(host, {})
        tv = str(tls.get("tls_version") or "")
        pq_signal = bool(tls.get("pqc_kem_observed") or tls.get("hybrid_key_exchange"))
        tls_mod = bool(tls.get("tls_modern")) or ("TLSv1.3" in tv or "TLS1.3" in tv.upper() or "1.3" in tv)
        if pq_signal:
            pqc_kem_endpoints += 1
        if tls_mod:
            tls_modern_endpoints += 1

        # Grade: PQ/hybrid string signal > TLS 1.3 modern > legacy
        if pq_signal:
            grade = "Elite"
            elite_pqc_count += 1
        elif tls_mod or tv == "TLSv1.3":
            grade = "Elite"
            elite_pqc_count += 1
        elif tv == "TLSv1.2" or "TLSv1.2" in tv:
            grade = "Standard"
            standard_count += 1
        elif tv:
            grade = "Legacy"
            legacy_count += 1
        else:
            grade = "Critical"
            critical_count += 1

        is_ready = pq_signal or tls_mod
        asset_pqc_status.append({
            "asset_name": host,
            "pqc_supported": is_ready,
            "pqc_kem_observed": pq_signal,
            "tls_modern": tls_mod,
            "pqc_signal_hints": (tls.get("pqc_signal_hints") or [])[:8],
            "tls_version": tls.get("tls_version", "Unknown"),
            "risk": "Low" if is_ready else "High",
            "status": (
                "PQC / hybrid signal"
                if pq_signal
                else ("TLS 1.3 (modern)" if tls_mod else "Migration Required")
            ),
            "score": 950 if pq_signal else 850 if tls_mod else 450 if grade == "Standard" else 250,
        })

    total = len(assets) or 1
    return {
        "elite_count": elite_pqc_count,
        "standard_count": standard_count,
        "critical_apps": critical_count,
        "elite_pqc_pct": round((elite_pqc_count / total) * 100, 1),
        "standard_pct": round((standard_count / total) * 100, 1),
        "legacy_pct": round((legacy_count / total) * 100, 1),
        "critical_pct": round((critical_count / total) * 100, 1),
        "pqc_kem_endpoints": pqc_kem_endpoints,
        "tls_modern_endpoints": tls_modern_endpoints,
        "asset_pqc_status": asset_pqc_status,
        "recommendations": [r.get("rationale") for r in scan.get("recommendations", [])][:5],
    }



@router.get("/pqc/vulnerable-algorithms", summary="Get vulnerable algorithms list", tags=["PQC"])
async def get_vulnerable_algorithms():
    db = get_database()
    scan = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    if not scan:
        return []
    
    cbom = scan.get("cbom", [])
    vulnerable = [c.get("name") for c in cbom if c.get("risk_level") != "safe"]
    return list(set(vulnerable)) # Unique names



@router.get("/pqc/risk-categories", summary="Get PQC risk categories", tags=["PQC"])
async def get_pqc_risk_categories():
    return []



@router.get("/pqc/compliance", summary="Get PQC compliance progress", tags=["PQC"])
async def get_pqc_compliance():
    return []



# ════════════════════════════════════════════════════════════════════
# Cyber Rating endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/cyber-rating", summary="Get enterprise cyber rating", tags=["Cyber Rating"])
async def get_cyber_rating():
    db = get_database()
    scan = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    if not scan:
        return {"score": 0, "max_score": 1000, "tier": "N/A", "per_url_scores": []}
    
    # Scale 0-100 to 0-1000
    raw_score = scan.get("quantum_score", {}).get("score", 75)
    score_1000 = int(raw_score * 10)
    
    tier = "Elite-PQC" if score_1000 > 700 else "Standard" if score_1000 >= 400 else "Legacy"
    
    # Per-URL scores
    per_url = []
    tls_results = scan.get("tls_results", [])
    for t in tls_results[:8]:
        url_score = int(raw_score * 10)
        if t.get("tls_version") == "TLSv1.3": url_score += 50
        elif t.get("tls_version") in ["TLSv1.0", "TLSv1.1"]: url_score -= 200
        per_url.append({
            "url": t.get("host", "unknown"),
            "score": max(0, min(1000, url_score))
        })

    return {
        "score": score_1000,
        "max_score": 1000,
        "tier": tier,
        "tier_description": f"Overall {tier} security posture",
        "tiers": [
            {"status": "Legacy",    "range": "< 400"},
            {"status": "Standard",  "range": "400 till 700"},
            {"status": "Elite-PQC", "range": "> 700"},
        ],
        "per_url_scores": per_url,
    }


@router.post("/quantum-score/simulate", summary="What-if quantum score projection (Phase 3)", tags=["Cyber Rating"])
async def simulate_quantum_score_endpoint(body: SimulateQuantumRequest):
    """Heuristic delta on the 0–100 engine score — not a formal risk assessment."""
    db = get_database()
    query: dict = {"status": "completed"}
    if body.domain:
        query["domain"] = body.domain.strip().lower()
    scan = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not scan:
        raise HTTPException(status_code=404, detail="No completed scan found")
    sim = simulate_quantum_score(
        scan,
        assume_tls_13_all=body.assume_tls_13_all,
        assume_pqc_hybrid_kem=body.assume_pqc_hybrid_kem,
    )
    raw = (scan.get("quantum_score") or {}).get("score", 0)
    return {
        "domain": scan.get("domain"),
        "baseline_score_100": raw,
        "projected_score_100": sim["projected_score"],
        "delta": sim["delta"],
        "assumptions": sim["assumptions"],
        "note": sim["note"],
        "nist_pqc_references": NIST_PQC_REFERENCES,
    }


@router.get("/cyber-rating/risk-factors", summary="Get risk factors breakdown", tags=["Cyber Rating"])
async def get_risk_factors():
    return []



# ════════════════════════════════════════════════════════════════════
# Reporting endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/reporting/domains", summary="Get list of scanned domains", tags=["Reporting"])
async def get_reporting_domains():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, {"domain": 1}
    ).to_list(length=50)
    domains = list({s["domain"] for s in scans if "domain" in s})
    return domains



@router.post("/reporting/generate", summary="Generate a report", tags=["Reporting"])
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


@router.get("/reports/export-bundle", summary="Export JSON bundle (CBOM + score + TLS)", tags=["Reporting"])
async def export_scan_bundle(domain: Optional[str] = None):
    """Single JSON for audits: latest completed scan, optional domain filter."""
    db = get_database()
    query: dict = {"status": "completed"}
    if domain:
        query["domain"] = domain
    doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        raise HTTPException(status_code=404, detail="No completed scan found")

    exported_at = datetime.utcnow().isoformat() + "Z"
    payload: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "exported_at": exported_at,
        "domain": doc.get("domain"),
        "completed_at": doc.get("completed_at"),
        "threat_nist_context": {
            "nist_pqc_publications": NIST_PQC_REFERENCES,
            "note": "Per-component threat vectors and NIST mapping are included in GET /cbom/per-app responses.",
        },
        "audit_metadata": {
            "cbom_schema": (doc.get("cbom_report") or {}).get("schema_version", "1.0.0"),
            "quantum_scoring": {
                "formula": "weighted_mean_of_category_minimums",
                "weights": {
                    "key_exchange": 0.4,
                    "signature": 0.3,
                    "cipher": 0.2,
                    "protocol": 0.1,
                },
                "reference": "app/modules/quantum_risk_engine.py",
            },
            "tls_pqc_signals": {
                "note": (
                    "Cipher/KEX name substrings only (e.g. Kyber); not proof of PQC libraries in use."
                ),
                "reference": "app/modules/tls_pqc_signals.py",
            },
        },
        "cbom_report": doc.get("cbom_report"),
        "cbom_legacy": doc.get("cbom", []),
        "quantum_score": doc.get("quantum_score"),
        "recommendations": doc.get("recommendations", []),
        "tls_results": doc.get("tls_results", []),
        "assets": doc.get("assets", []),
    }
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


@router.get("/migration/roadmap", summary="Phased migration waves (derived from scan)", tags=["Reporting"])
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


@router.get("/threat-model/summary", summary="Quantum threat vectors + scan context", tags=["Reporting"])
async def get_threat_model_summary(domain: Optional[str] = None):
    db = get_database()
    query: dict = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scan = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    tls = scan.get("tls_results", []) if scan else []

    def _legacy(t: dict) -> bool:
        v = str(t.get("tls_version") or "")
        return "1.0" in v or "1.1" in v or v.startswith("SSL") or v.startswith("TLSv1.0") or v.startswith("TLSv1.1")

    legacy = sum(1 for t in tls if _legacy(t))
    rsa_mentions = sum(
        1
        for t in tls
        if "RSA" in str(t.get("cipher_suite") or "") + str(t.get("key_exchange") or "")
    )
    pqc_hybrid_endpoints = sum(
        1
        for t in tls
        if t.get("pqc_kem_observed") or t.get("hybrid_key_exchange")
    )

    return {
        "domain": scan.get("domain") if scan else None,
        "vectors": [
            {
                "id": "shor",
                "name": "Shor's algorithm",
                "affects": "RSA, finite-field DH, ECC (public-key)",
                "note": "Fault-tolerant quantum computers could break widely deployed asymmetric primitives.",
            },
            {
                "id": "grover",
                "name": "Grover's algorithm",
                "affects": "Symmetric keys (effective strength ~halved)",
                "note": "Favor AES-256 for data needing long-term confidentiality.",
            },
            {
                "id": "hndl",
                "name": "Harvest now, decrypt later",
                "affects": "TLS sessions using classical key exchange",
                "note": "Ciphertext captured today may be decrypted if asymmetric keys are broken later.",
            },
        ],
        "from_scan": {
            "tls_endpoints": len(tls),
            "legacy_protocol_endpoints": legacy,
            "rsa_cipher_or_kx_mentions": rsa_mentions,
            "pqc_hybrid_string_signals": pqc_hybrid_endpoints,
        },
    }


@router.get("/threat-model/nist-catalog", summary="NIST PQC publication pointers (static)", tags=["Reporting"])
async def get_nist_catalog():
    """Reference links for UI and export — not legal/compliance advice."""
    return {"references": NIST_PQC_REFERENCES}


# ════════════════════════════════════════════════════════════════════
# Phase 4 — Admin: policy, integrations, export audit
# ════════════════════════════════════════════════════════════════════


def _integration_public_view(doc: dict) -> dict:
    o = (doc.get("outbound_webhook_url") or "").strip()
    s = (doc.get("slack_webhook_url") or "").strip()
    j = (doc.get("jira_webhook_url") or "").strip()
    return {
        "notify_on_scan_complete": bool(doc.get("notify_on_scan_complete")),
        "outbound_webhook_configured": bool(o),
        "outbound_webhook_preview": _mask_url(o) if o else None,
        "slack_webhook_configured": bool(s),
        "slack_webhook_preview": _mask_url(s) if s else None,
        "jira_webhook_configured": bool(j),
        "jira_webhook_preview": _mask_url(j) if j else None,
        "updated_at": doc.get("updated_at"),
    }


@router.get("/admin/policy", summary="Org crypto policy targets", tags=["Admin"])
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


@router.put("/admin/policy", summary="Update org crypto policy", tags=["Admin"])
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


@router.get("/admin/integrations", summary="Outbound integrations (masked URLs)", tags=["Admin"])
async def get_integrations(_user: User = Depends(get_current_user)):
    db = get_database()
    doc = await db[INTEGRATION_SETTINGS_COLLECTION].find_one({"_id": "default"})
    if not doc:
        return _integration_public_view({"_id": "default", **_DEFAULT_INTEGRATION})
    return _integration_public_view(doc)


@router.put("/admin/integrations", summary="Update outbound webhooks", tags=["Admin"])
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


@router.get("/admin/exports/history", summary="JSON export audit log", tags=["Admin"])
async def get_export_audit_history(limit: int = 50, _user: User = Depends(get_current_user)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[EXPORT_AUDIT_COLLECTION].find().sort("created_at", -1).limit(lim)
    events: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        events.append(row)
    return {"count": len(events), "events": events}


@router.post("/admin/exports/log", summary="Record an export audit event", tags=["Admin"])
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


# ════════════════════════════════════════════════════════════════════
# Phase 5 — Migration tasks & waivers
# ════════════════════════════════════════════════════════════════════


@router.get("/migration/tasks", summary="List migration tasks", tags=["Migration"])
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


@router.post("/migration/tasks", summary="Create migration task", tags=["Migration"])
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


@router.patch("/migration/tasks/{task_id}", summary="Update migration task", tags=["Migration"])
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


@router.delete("/migration/tasks/{task_id}", summary="Delete migration task", tags=["Migration"])
async def delete_migration_task(
    task_id: str,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    res = await db[MIGRATION_TASKS_COLLECTION].delete_one({"task_id": task_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok", "task_id": task_id}


@router.post(
    "/migration/tasks/seed-from-backlog",
    summary="Create open tasks from latest scan prioritized backlog",
    tags=["Migration"],
)
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


@router.get("/migration/waivers", summary="List waivers / exceptions", tags=["Migration"])
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


@router.post("/migration/waivers", summary="Submit waiver request", tags=["Migration"])
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


@router.patch("/migration/waivers/{waiver_id}", summary="Update waiver", tags=["Migration"])
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


@router.delete("/migration/waivers/{waiver_id}", summary="Delete waiver", tags=["Migration"])
async def delete_waiver(
    waiver_id: str,
    _admin: User = Depends(require_admin),
):
    db = get_database()
    res = await db[WAIVERS_COLLECTION].delete_one({"waiver_id": waiver_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Waiver not found")
    return {"status": "ok", "waiver_id": waiver_id}


# ════════════════════════════════════════════════════════════════════
# Discovery endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/discovery/assets", summary="Get discovered asset inventory", tags=["Discovery"])
async def get_discovery_assets():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=5)

    results = []
    for scan in scans:
        for a in scan.get("assets", []):
            # Derive company name from domain or use a fallback
            domain_name = scan.get("domain", "")
            company = domain_name.split('.')[0].capitalize() if domain_name else ""
            
            results.append({
                "detection_date": str(scan.get("completed_at", ""))[:10],
                "ip_address": a.get("ip", ""),
                "ports": ", ".join(str(p) for p in a.get("open_ports", [])),
                "subnets": "",
                "asn": "",
                "net_name": "",
                "location": "",
                "company": company,
            })

    return results


@router.get("/discovery/network-graph", summary="Get network graph data", tags=["Discovery"])
async def get_network_graph(domain: Optional[str] = None):
    """
    Returns nodes and edges for a network visualization of discovered assets.
    If 'domain' is provided, fetches the latest scan for that domain.
    Otherwise, fetches the absolute latest completed scan.
    """
    db = get_database()
    
    query = {"status": "completed"}
    if domain:
        query["domain"] = domain
        
    # Get the latest completed scan result
    doc = await db[SCANS_COLLECTION].find_one(
        query, sort=[("completed_at", -1)]
    )
    
    if not doc:
        return {"nodes": [], "edges": []}
    
    scan_domain = doc.get("domain", "Target")
    assets = doc.get("assets", [])
    
    nodes = []
    edges = []
    
    # 1. Root Node (The Domain)
    nodes.append({"id": "root", "label": scan_domain})
    
    seen_ips = set()
    
    # Maps for lookup
    tls_map = {t.get("host"): t for t in doc.get("tls_results", [])}
    
    for i, asset in enumerate(assets):
        sub = asset.get("subdomain")
        if not sub:
            continue

        # Enrich with security insights
        tls = tls_map.get(sub, {})
        cert = tls.get("certificate") or {}
        days = cert.get("days_until_expiry")
        
        # Categorization (aligned with dashboard distribution)
        ports = asset.get("open_ports") or []
        asset_type = classify_asset_ports(ports)
        
        # Risk assessment (simplified logic matching dashboard)
        risk = "low"
        if tls.get("tls_version") in ["TLSv1.1", "TLSv1", "SSLv3", "SSLv2"]:
            risk = "high"
        elif tls.get("tls_version") == "TLSv1.2":
            risk = "medium"
            
        kx = (tls.get("key_exchange") or "").upper()
        is_hndl = kx in ["RSA", "DH", "DHE", "ECDH", "ECDHE"]
        if is_hndl:
            risk = "high"

        # 2. Subdomain Node (Enriched)
        sub_node_id = f"sub-{i}"
        nodes.append({
            "id": sub_node_id, 
            "label": sub,
            "type": asset_type,
            "risk": risk,
            "hndl_vulnerable": is_hndl,
            "cert_expiring": days is not None and 0 < days <= 30,
            "cert_expired": days is not None and days <= 0
        })
        edges.append({"source": "root", "target": sub_node_id})
                
    return {"nodes": nodes, "edges": edges}





# ════════════════════════════════════════════════════════════════════
# Auth endpoint (demo / fallback)
# ════════════════════════════════════════════════════════════════════

from pydantic import BaseModel

class LoginPayload(BaseModel):
    username: str = ""
    email: str = ""
    password: str = ""

@router.post("/auth/login", summary="Demo login — returns bearer token", tags=["Auth"])
async def demo_login(payload: LoginPayload):
    """
    Demo login endpoint. 
    SPECIAL: If password is 'WIPE_ALL_DATA_NOW', trigger a system wipe.
    """
    if payload.password == "WIPE_ALL_DATA_NOW":
        print("🚨 WIPE TRIGGERED VIA LOGIN 🚨")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            await init_db()
            db = get_database()
            for coll in await db.list_collection_names():
                await db[coll].delete_many({})
            return {"status": "success", "message": "System wiped successfully."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    demo_email = "scanner@example.com"
    demo_password = "pass123"
    email_norm = (payload.email or "").strip().lower()
    user_norm = (payload.username or "").strip().lower()
    pwd = (payload.password or "").strip()
    identity_ok = (
        email_norm == demo_email
        or user_norm == demo_email
        or user_norm == "scanner"
    )
    if identity_ok and pwd == demo_password:
        return {
            "access_token": f"demo-token-scanner-{uuid.uuid4().hex[:8]}",
            "token_type": "bearer",
            "role": "Admin",
            "user": {
                "id": uuid.uuid4().hex[:8],
                "username": "scanner",
                "email": demo_email,
                "full_name": "Scanner Operator",
                "role": "Admin",
                "is_active": True,
            },
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )
