"""
QuantumShield — API Routes (v1 scanner + all dashboard endpoints)

Endpoints:
  POST /scan                      → trigger a full scan
  GET  /results/{domain}          → retrieve scan results
  GET  /cbom/{domain}             → retrieve CBOM report
  GET  /quantum-score/{domain}    → retrieve quantum readiness score

  GET  /dashboard/summary         → dashboard KPI stats
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
  GET  /discovery/assets          → discovered asset inventory (tabbed view)
  GET  /discovery/network-graph   → network graph nodes + edges
  POST /auth/login                → demo login (returns JWT-style token)
"""

import asyncio
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from app.db.connection import get_database
from app.db.models import (
    CBOMReport,
    CryptoComponent,
    QuantumScore,
    Recommendation,
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
from app.core.ws_manager import manager as ws_manager
from app.utils.logger import get_logger

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


# ── Helper: run full pipeline ────────────────────────────────────

async def _run_scan_pipeline(scan_id: str, request: ScanRequest) -> None:
    """
    Execute the complete scanning pipeline in the background.

    Pipeline stages:
      1. Asset discovery (subdomains + port scan)
      2. TLS scanning (all protocols, all ciphers, cert chain)
      3. Crypto analysis of TLS results
      4. Quantum risk scoring
      5. CBOM generation
      6. PQC recommendations
      7. HTTP security headers scan
      8. CVE / known-attack mapping
      9. PostgreSQL sync

    Results are persisted to MongoDB at each stage.
    """
    db = get_database()
    collection = db[SCANS_COLLECTION]

    try:
        # Mark as running
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"status": ScanStatus.RUNNING.value, "started_at": datetime.utcnow()}},
        )

        # ── Stage 1: Asset Discovery ─────────────────────────────
        logger.info("[%s] Stage 1/9: Asset Discovery", scan_id)

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

        # ── New Stage: DNS Record Collection ──
        logger.info("[%s] Collecting DNS records for %s", scan_id, request.domain)
        dns_records = await asset_discovery.get_ns_records(request.domain)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"dns_records": [r.model_dump() for r in dns_records]}},
        )

        def infer_type(ports):
            p = set(ports)
            if any(x in p for x in [80, 443, 8080, 8443]): return "web_app"
            if any(x in p for x in [22, 3389]): return "server"
            return "other"

        web_count = sum(1 for a in assets if infer_type(a.open_ports) == "web_app")
        srv_count = sum(1 for a in assets if infer_type(a.open_ports) == "server")

        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {
                "total_assets": len(assets),
                "public_web_apps": web_count,
                "servers": srv_count,
                "apis": 0,
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
        logger.info("[%s] Stage 2/9: TLS Scanning", scan_id)
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
        logger.info("[%s] Stage 3/9: Crypto Analysis", scan_id)
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
        logger.info("[%s] Stage 4/9: Quantum Risk Scoring", scan_id)
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
        logger.info("[%s] Stage 5/9: CBOM Generation", scan_id)
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
        logger.info("[%s] Stage 6/9: PQC Recommendations", scan_id)
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
        logger.info("[%s] Stage 7/9: HTTP Security Headers", scan_id)
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
        logger.info("[%s] Stage 8/8: CVE Mapping", scan_id)
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

        logger.info("[%s] ✅ Scan pipeline completed (8/8 stages).", scan_id)

    except Exception as exc:
        logger.exception("[%s] ❌ Scan pipeline failed: %s", scan_id, exc)
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": ScanStatus.FAILED.value,
                "error": str(exc),
                "completed_at": datetime.utcnow(),
            }},
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
    background_tasks.add_task(_run_scan_pipeline, scan_id, request)

    logger.info("Scan %s queued for domain %s", scan_id, request.domain)
    return {
        "scan_id": scan_id,
        "domain": request.domain,
        "status": ScanStatus.PENDING.value,
        "message": "Scan initiated — poll GET /results/{domain} for progress.",
    }


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


    return cbom_report


@router.get("/cbom/summary", summary="Get CBOM summary statistics", tags=["CBOM"])
async def get_cbom_summary():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find({"status": "completed"}).to_list(length=100)

    total_sites = len(scans)
    total_components = 0
    active_certs = 0
    weak_crypto = 0
    cert_issues = 0

    for s in scans:
        all_cbom = s.get("cbom", [])
        total_components += len(all_cbom)
        weak_crypto += sum(1 for c in all_cbom if c.get("risk_level") in ["critical", "high"])
        
        tls_results = s.get("tls_results", [])
        active_certs += len(tls_results)
        for t in tls_results:
            days = (t.get("certificate") or {}).get("days_until_expiry")
            if days is not None and days <= 30:
                cert_issues += 1
    
    return {
        "total_applications": total_sites,
        "sites_surveyed": total_components,
        "active_certificates": active_certs, 
        "weak_cryptography": weak_crypto,
        "certificate_issues": cert_issues,
    }


@router.get("/cbom/charts", summary="Get CBOM chart data", tags=["CBOM"])
async def get_cbom_charts():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find({"status": "completed"}).to_list(length=100)

    key_lengths: dict = {}
    tls_versions: dict = {}
    cas: dict = {}
    cipher_usage: dict = {}

    for scan in scans:
        for t in scan.get("tls_results", []):
            kl = str(t.get("cipher_bits") or t.get("key_length") or "2048")
            tv = t.get("tls_version", "TLS 1.2")
            ca = (t.get("certificate") or {}).get("issuer", "Unknown") or "Unknown"
            cipher = t.get("cipher_suite", "Unknown")

            key_lengths[kl] = key_lengths.get(kl, 0) + 1
            tls_versions[tv] = tls_versions.get(tv, 0) + 1
            cas[ca] = cas.get(ca, 0) + 1
            cipher_usage[cipher] = cipher_usage.get(cipher, 0) + 1

    return {
        "key_length_distribution": [{"name": k, "count": v} for k, v in key_lengths.items()],
        "top_certificate_authorities": [{"name": k, "value": v} for k, v in cas.items()],
        "encryption_protocols": [{"name": k, "value": v} for k, v in tls_versions.items()],
        "cipher_usage": [{"name": k, "value": v} for k, v in cipher_usage.items()],
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

@router.get("/dashboard/summary", summary="Get dashboard summary stats", tags=["Dashboard"])
async def get_dashboard_summary():
    db = get_database()
    scans = await db[SCANS_COLLECTION].find(
        {"status": "completed"}, sort=[("completed_at", -1)]
    ).to_list(length=100)

    total_assets = sum(len(s.get("assets", [])) for s in scans)
    tls_all = []
    for s in scans:
        tls_all.extend(s.get("tls_results", []))
    expiring = sum(
        1 for t in tls_all
        if t.get("certificate", {}) and
        0 < (t.get("certificate", {}).get("days_until_expiry") or 365) <= 30
    )
    high_risk = sum(
        1 for s in scans
        if s.get("quantum_score", {}).get("risk_level") in ["high", "critical"]
    )

    public_web_apps = 0
    apis = 0
    servers = 0
    
    for s in scans:
        for a in s.get("assets", []):
            ports = a.get("open_ports", [])
            if any(p in [80, 443, 8080, 8443] for p in ports):
                public_web_apps += 1
            elif any(p in [22, 21, 3306, 5432] for p in ports):
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
            
            # Infer fields
            ports = a.get("open_ports", [443])
            a_type = "Web App" if any(p in [80, 443, 8080, 8443] for p in ports) else "API"
            
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
                "owner": "IT Team",
                "risk": "Low" if tls.get("tls_version") == "TLSv1.3" else "Medium",
                "hndlRisk": False,
                "certificate_status": cert_status_slug,
                "certStatus": cert_status_slug.replace("_", " ").title(),
                "pqcStatus": "Ready" if tls.get("tls_version") == "TLSv1.3" else "Not Ready",
                "key_length": str(tls.get("cipher_bits") or "2048"),
                "last_scan": str(scan.get("completed_at", ""))[:10],
                "tls_version": tls.get("tls_version"),
                "cipher_suite": tls.get("cipher_suite"),
            })

    return {
        "items": assets,
        "total": len(assets),
        "page": 1,
        "page_size": 100
    }


    return {
        "total": 0, "web_apps": 0, "apis": 0,
        "servers": 0, "gateways": 0, "other": 0,
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
            ports = a.get("open_ports", [])
            if any(p in [80, 443, 8080, 8443] for p in ports):
                public_web_apps += 1
            elif any(p in [22, 21, 3306, 5432] for p in ports):
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
                "key_length": str(t.get('cipher_bits') or 2048),
                "cipher_suite": t.get("cipher_suite", "TLS_AES_256_GCM_SHA384"),
                "tls_version": t.get("tls_version", "TLS 1.3"),
                "certificate_authority": cert.get("issuer", "DigiCert"),
                "pqcStatus": "not-ready",
            })

    return results



# ════════════════════════════════════════════════════════════════════
# PQC Posture endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/pqc/posture", summary="Get PQC posture overview", tags=["PQC"])
async def get_pqc_posture():
    return {
        "migration_score": 0,
        "vulnerable_algorithms": 0,
        "needs_monitoring": 0,
        "quantum_safe": 0,
        "elite_pqc_ready_pct": 0,
        "standard_pct": 0,
        "legacy_pct": 0,
        "critical_apps": 0,
    }



@router.get("/pqc/vulnerable-algorithms", summary="Get vulnerable algorithms list", tags=["PQC"])
async def get_vulnerable_algorithms():
    return []



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
    doc = await db[SCANS_COLLECTION].find_one({}, sort=[("completed_at", -1)])
    
    # Base score out of 100
    scaled_score = 0
    tier = "N/A"
    
    return {
        "score": scaled_score,
        "max_score": 1000,
        "tier": tier,

        "tier_description": "Indicates a stronger security posture",
        "tiers": [
            {"status": "Legacy",    "range": "< 400"},
            {"status": "Standard",  "range": "400 till 700"},
            {"status": "Elite-PQC", "range": "> 700"},
        ],
        "per_url_scores": [],
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
            results.append({
                "detection_date": str(scan.get("completed_at", "2026-03-12"))[:10],
                "ip_address": a.get("ip", ""),
                "ports": ", ".join(str(p) for p in a.get("open_ports", [80, 443])),
                "subnets": "103.107.224.0/22",
                "asn": "AS9583",
                "net_name": "PNB-NET",
                "location": "India",
                "company": "Punjab National Bank",
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
    
    for i, asset in enumerate(assets):
        sub = asset.get("subdomain")
        
        if not sub:
            continue

        # 2. Subdomain Node
        sub_node_id = f"sub-{i}"
        nodes.append({"id": sub_node_id, "label": sub})
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

    username = payload.username or payload.email.split("@")[0]
    password = payload.password

    demo_users = {
        "admin":           {"role": "Admin",    "name": "Admin User"},
        "employee":        {"role": "Employee", "name": "John Doe"},
        "hackathon_user":  {"role": "Admin",    "name": "Hackathon User"},
        "hackathon_user@pnb.bank.in": {"role": "Admin", "name": "Hackathon User"},
    }

    user = demo_users.get(username.lower()) or demo_users.get(username)
    if user and password == "password":

        return {
            "access_token": f"demo-token-{username}-{uuid.uuid4().hex[:8]}",
            "token_type": "bearer",
            "role": user["role"],
            "user": {
                "id": uuid.uuid4().hex[:8],
                "username": username,
                "email": f"{username}@pnb.bank.in",
                "full_name": user["name"],
                "role": user["role"],
                "is_active": True,
            },
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials. Use password: 'password'",
    )
