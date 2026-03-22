"""
QuantumShield — API Routes

REST endpoints for the scanning pipeline:

  POST /scan                 → trigger a full scan
  GET  /results/{domain}     → retrieve scan results
  GET  /cbom/{domain}        → retrieve CBOM report
  GET  /quantum-score/{domain} → retrieve quantum readiness score
"""

import asyncio
import uuid
from datetime import datetime
from typing import List

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
        logger.info("[%s] Stage 1/6: Asset Discovery", scan_id)
        
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

        # Calculate live metrics after Stage 1
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
                "apis": 0 # Heuristic placeholder
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
            {"$set": {"assets": [a.model_dump() for a in assets]}},
        )

        # ── Stage 2: TLS Scanning ────────────────────────────────
        logger.info("[%s] Stage 2/6: TLS Scanning", scan_id)
        tls_tasks = []
        for asset in assets:
            for port in asset.open_ports:
                tls_tasks.append(tls_scanner.scan_tls(asset.subdomain, port))

        tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)
        # Use TLSInfo for explicit type filtering to satisfy linting
        tls_results = [r for r in tls_results if isinstance(r, TLSInfo)]

        # Calculate metrics after Stage 2
        expiring = sum(1 for t in tls_results if t.certificate and (t.certificate.days_until_expiry or 365) <= 30)
        
        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {
                "expiring_certificates": expiring
            }
        }, scan_id)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"tls_results": [t.model_dump() for t in tls_results]}},
        )

        # ── Stage 3: Crypto Analysis ────────────────────────────
        logger.info("[%s] Stage 3/6: Crypto Analysis", scan_id)
        all_components: List[CryptoComponent] = []
        for tls_info in tls_results:
            components = crypto_analyzer.analyze(tls_info)
            all_components.extend(components)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"cbom": [c.model_dump() for c in all_components]}},
        )

        # ── Stage 4: Quantum Risk Scoring ────────────────────────
        logger.info("[%s] Stage 4/6: Quantum Risk Scoring", scan_id)
        q_score = quantum_risk_engine.calculate_score(all_components)

        # Calculate metrics after Stage 4
        is_high_risk = 1 if q_score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] else 0
        
        await ws_manager.broadcast({
            "type": "metrics",
            "status": "update",
            "data": {
                "high_risk_assets": is_high_risk # This is simplified, ideally it's per asset
            }
        }, scan_id)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"quantum_score": q_score.model_dump()}},
        )

        # ── Stage 5: CBOM Generation ────────────────────────────
        logger.info("[%s] Stage 5/6: CBOM Generation", scan_id)
        scan_data = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            cbom=all_components,
        )
        cbom_report = cbom_generator.generate_cbom(scan_data)
        # Store the CBOM report as a sub-document
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"cbom_report": cbom_report.model_dump(mode="json")}},
        )

        # ── Stage 6: Recommendations ────────────────────────────
        logger.info("[%s] Stage 6/8: PQC Recommendations", scan_id)
        recs = recommendation_engine.get_recommendations(all_components, q_score)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"recommendations": [r.model_dump() for r in recs]}},
        )

        # ── Stage 7: HTTP Security Headers ───────────────────────
        logger.info("[%s] Stage 7/8: HTTP Security Headers", scan_id)
        headers_tasks = [scan_headers(asset.subdomain) for asset in assets]
        headers_results = await asyncio.gather(*headers_tasks, return_exceptions=True)
        headers_results = [r for r in headers_results if not isinstance(r, Exception)]

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"headers_results": [h.model_dump() for h in headers_results]}},
        )

        # ── Stage 8: CVE / Known-Attack Mapping ──────────────────
        logger.info("[%s] Stage 8/8: CVE Mapping", scan_id)
        cve_findings = map_cves(tls_results)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "cve_findings": [c.model_dump() for c in cve_findings],
                "status": ScanStatus.COMPLETED.value,
                "completed_at": datetime.utcnow(),
            }},
        )

        # ── Stage 9: Sync to PostgreSQL for Dashboard ────────────
        try:
            from app.db.sync import sync_scan_to_postgres
            logger.info("[%s] Stage 9: Syncing to PostgreSQL Dashboard", scan_id)
            await sync_scan_to_postgres(
                request.domain, 
                assets, 
                tls_results, 
                all_components, 
                q_score.model_dump()
            )
        except Exception as sync_exc:
            logger.error("[%s] ⚠️ PostgreSQL sync failed: %s", scan_id, sync_exc)

        await ws_manager.broadcast({
            "type": "status",
            "stage": 9,
            "status": "completed",
            "message": "Scan completed successfully."
        }, scan_id)

        logger.info("[%s] ✅ Scan pipeline completed successfully (9/9 stages).", scan_id)

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


# ── Endpoints ────────────────────────────────────────────────────

@router.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a full cryptographic scan",
    response_description="Scan accepted — returns scan ID for tracking.",
)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start an asynchronous scan of the given domain.

    The scan runs in the background through all 6 pipeline stages.
    Use `GET /results/{domain}` or the returned `scan_id` to poll
    for results.
    """
    scan_id = uuid.uuid4().hex
    db = get_database()

    # Persist initial record
    initial = ScanResult(
        scan_id=scan_id,
        domain=request.domain,
        status=ScanStatus.PENDING,
    )
    await db[SCANS_COLLECTION].insert_one(initial.model_dump(mode="json"))

    # Fire off the pipeline
    background_tasks.add_task(_run_scan_pipeline, scan_id, request)

    logger.info("Scan %s queued for domain %s", scan_id, request.domain)
    return {
        "scan_id": scan_id,
        "domain": request.domain,
        "status": ScanStatus.PENDING.value,
        "message": "Scan initiated — poll GET /results/{domain} for progress.",
    }


@router.get(
    "/results/{domain}",
    summary="Get scan results for a domain",
    response_description="Latest scan result with all pipeline outputs.",
)
async def get_results(domain: str):
    """
    Retrieve the most recent scan result for a domain.

    Returns the full result including TLS info, CBOM, quantum score,
    and PQC recommendations.
    """
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain},
        sort=[("started_at", -1)],
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )
    doc.pop("_id", None)
    return doc


@router.get(
    "/cbom/{domain}",
    summary="Get Cryptographic Bill of Materials",
    response_description="Structured CBOM report for the domain.",
)
async def get_cbom(domain: str):
    """
    Retrieve the CBOM report for the most recent scan of a domain.

    The CBOM lists all cryptographic components discovered, with
    their risk levels and quantum vulnerability status.
    """
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain},
        sort=[("started_at", -1)],
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )

    cbom_report = doc.get("cbom_report")
    if not cbom_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CBOM not yet generated for domain: {domain} (scan may still be running).",
        )
    return cbom_report


@router.get(
    "/quantum-score/{domain}",
    summary="Get Quantum Readiness Score",
    response_description="Quantum readiness score with breakdown.",
)
async def get_quantum_score(domain: str):
    """
    Retrieve the Quantum Readiness Score for a domain.

    Score is 0–100, where higher values indicate better quantum
    preparedness. Includes a per-category breakdown and risk level.
    """
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": domain},
        sort=[("started_at", -1)],
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )

    q_score = doc.get("quantum_score")
    if not q_score:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Quantum score not yet calculated for domain: {domain}.",
        )

    return {
        "domain": domain,
        "quantum_score": q_score,
        "recommendations": doc.get("recommendations", []),
    }
