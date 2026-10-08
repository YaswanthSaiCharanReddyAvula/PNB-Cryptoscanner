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



@router.get("/inventory/summary", tags=["Assets"])
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
                    "buckets": list(asset.get("buckets") or []),
                    "hosting_hint": asset.get("hosting_hint"),
                    "surface": asset.get("surface"),
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
                        "buckets": list(asset.get("buckets") or []),
                        "hosting_hint": asset.get("hosting_hint"),
                        "surface": asset.get("surface"),
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


@router.post("/inventory/sources/import", tags=["Assets"])
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


@router.get("/inventory/registered", tags=["Assets"])
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


@router.post("/inventory/sbom", tags=["Assets"])
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


@router.put("/assets/metadata", tags=["Assets"])
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


@router.post("/assets/metadata/bulk", tags=["Assets"])
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


@router.get("/assets", tags=["Assets"])
async def get_assets():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=10)

    # One row per hostname; newest completed scan wins (scans are newest-first).
    seen_hosts: set[str] = set()
    assets: List[dict] = []
    for scan in scans:
        tls_map = {t.get("host"): t for t in scan.get("tls_results", [])}
        for a in scan.get("assets", []) or []:
            host = (a.get("subdomain") or "").strip()
            if not host:
                continue
            key = host.lower()
            if key in seen_hosts:
                continue
            seen_hosts.add(key)

            tls = tls_map.get(host, {})
            cert = tls.get("certificate") or {}

            a_type = asset_type_label(classify_asset_service(a.get("services") or []))

            days = cert.get("days_until_expiry")
            if days is None:
                cert_status_slug = "unknown"
            elif days <= 0:
                cert_status_slug = "expired"
            elif days <= 30:
                cert_status_slug = "expiring_soon"
            else:
                cert_status_slug = "valid"

            quantum_score = scan.get("quantum_score") if isinstance(scan, dict) else None
            risk_level = ""
            if isinstance(quantum_score, dict):
                risk_level = str(quantum_score.get("risk_level") or "")

            assets.append(
                {
                    "asset_name": host,
                    "url": f"https://{host}",
                    "ipv4": a.get("ip", ""),
                    "ipv6": "",
                    "type": a_type,
                    "owner": "",
                    "risk": risk_level.capitalize(),
                    "hndlRisk": False,
                    "certificate_status": cert_status_slug,
                    "certStatus": cert_status_slug.replace("_", " ").title()
                    if cert_status_slug != "unknown"
                    else "",
                    "pqcStatus": "Ready" if tls.get("tls_version") == "TLSv1.3" else "",
                    "key_length": str(tls.get("cipher_bits") or ""),
                    "last_scan": str(scan.get("completed_at", ""))[:10],
                    "tls_version": tls.get("tls_version", ""),
                    "cipher_suite": tls.get("cipher_suite", ""),
                    "open_ports": list(a.get("open_ports") or []),
                    "buckets": list(a.get("buckets") or []),
                    "hosting_hint": a.get("hosting_hint") or "",
                    "surface": a.get("surface") or "",
                }
            )

    return {
        "items": assets,
        "total": len(assets),
        "page": 1,
        "page_size": 100,
    }


@router.get("/assets/distribution", tags=["Assets"])
async def get_asset_distribution():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=10)

    # Unique hosts only; classify using the newest scan row for each (same as GET /assets).
    seen_hosts: set[str] = set()
    public_web_apps = 0
    apis = 0
    servers = 0

    for s in scans:
        for a in s.get("assets", []) or []:
            sub = (a.get("subdomain") or "").strip()
            if not sub:
                continue
            key = sub.lower()
            if key in seen_hosts:
                continue
            seen_hosts.add(key)

            cat = classify_asset_service(a.get("services") or [])
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


@router.get("/dns/nameserver-records", tags=["Assets"])
async def get_nameserver_records():
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"status": "completed"}, sort=[("completed_at", -1)]
    )
    if not doc:
        return []
    return doc.get("dns_records", [])


@router.get("/discovery/assets", tags=["Assets"])
async def get_discovery_assets():
    """
    Flat list of discovered hosts for Asset Discovery UI (Domains tab).

    Frontend expects per row: `asset` or `name` (FQDN), `last_seen` (ISO-ish),
    plus optional display fields. Deduplicates by subdomain keeping the newest scan.
    """
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=25)

    seen_subdomains: set[str] = set()
    results: List[dict] = []

    for scan in scans:
        completed = scan.get("completed_at")
        last_seen = ""
        if completed is not None:
            last_seen = completed.isoformat() if hasattr(completed, "isoformat") else str(completed)
        detection_date = last_seen[:10] if last_seen else ""
        root_domain = (scan.get("domain") or "").strip().lower()

        for a in scan.get("assets", []) or []:
            sub = (a.get("subdomain") or "").strip()
            if not sub:
                continue
            key = sub.lower()
            if key in seen_subdomains:
                continue
            seen_subdomains.add(key)

            company_from_root = root_domain.split(".")[0].capitalize() if root_domain else ""
            company_from_host = sub.split(".")[0].capitalize() if sub else ""

            results.append(
                {
                    # Domains table (AssetDiscovery.tsx)
                    "asset": sub,
                    "name": sub,
                    "last_seen": last_seen or detection_date,
                    "detection_date": detection_date,
                    "registration_date": "",
                    "registrar": "",
                    "company": company_from_root or company_from_host,
                    # Extra context for other clients / future columns
                    "ip_address": a.get("ip") or "",
                    "open_ports": list(a.get("open_ports") or []),
                    "ports": ", ".join(str(p) for p in (a.get("open_ports") or [])),
                    "scan_domain": root_domain,
                    "owner": a.get("owner") or "",
                    "environment": a.get("environment") or "",
                    "criticality": a.get("criticality") or "",
                    "buckets": list(a.get("buckets") or []),
                    "hosting_hint": a.get("hosting_hint") or "",
                    "surface": a.get("surface") or "",
                }
            )

    return results


@router.get("/discovery/network-graph", tags=["Assets"])
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
        asset_type = classify_asset_service(asset.get("services") or [])
        
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


# ── Phase 3: Canonical Data API ─────────────────────────────────

@router.get("/canonical-inventory/{scan_id}", tags=["Canonical Inventory"])
async def get_canonical_inventory(scan_id: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one({"scan_id": scan_id})
    if not doc or "canonical_inventory" not in doc or not doc["canonical_inventory"]:
        raise HTTPException(status_code=404, detail="Canonical inventory not found for scan")
    return doc["canonical_inventory"]

@router.get("/canonical-inventory/{scan_id}/assets", tags=["Canonical Inventory"])
async def get_canonical_assets(scan_id: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one({"scan_id": scan_id})
    if not doc or "canonical_inventory" not in doc or not doc["canonical_inventory"]:
        raise HTTPException(status_code=404, detail="Canonical inventory not found for scan")
    return doc["canonical_inventory"].get("assets", {})

@router.get("/canonical-inventory/{scan_id}/findings", tags=["Canonical Inventory"])
async def get_canonical_findings(scan_id: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one({"scan_id": scan_id})
    if not doc or "canonical_inventory" not in doc or not doc["canonical_inventory"]:
        raise HTTPException(status_code=404, detail="Canonical inventory not found for scan")
    return doc["canonical_inventory"].get("findings", [])

@router.get("/canonical-inventory/{scan_id}/evidence", tags=["Canonical Inventory"])
async def get_canonical_evidence(scan_id: str):
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one({"scan_id": scan_id})
    if not doc or "canonical_inventory" not in doc or not doc["canonical_inventory"]:
        raise HTTPException(status_code=404, detail="Canonical inventory not found for scan")
    return doc["canonical_inventory"].get("evidence", [])
