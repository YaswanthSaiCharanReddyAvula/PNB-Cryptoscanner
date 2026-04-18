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
NOTIFICATIONS_COLLECTION = "notifications"

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
    """Run pipeline with global concurrency cap (Phase 2 portfolio scans).

    Delegates to the new custom scanner engine when ``scan_depth`` is
    present on *request* (or when the ``SCANNER_SCAN_DEPTH`` env var is
    set).  Falls back to the legacy 8-stage pipeline otherwise so that
    existing behaviour is preserved.
    """
    async with _scan_sem:
        scan_depth = getattr(request, "scan_depth", None) or settings.SCANNER_SCAN_DEPTH
        if scan_depth in ("fast", "standard", "aggressive"):
            try:
                await _run_custom_scan_pipeline(scan_id, request, scan_depth)
                return
            except Exception:
                logger.warning(
                    "[%s] Custom engine failed, falling back to legacy pipeline",
                    scan_id, exc_info=True,
                )
        await _run_scan_pipeline(scan_id, request)




async def _run_custom_scan_pipeline(
    scan_id: str, request: ScanRequest, scan_depth: str = "standard"
) -> None:
    """Execute the new custom scanner engine (zero external binaries)."""
    from app.scanner.pipeline import PipelineManager, ScanContext
    from app.scanner.engines.adaptive import AdaptiveRateController
    from app.scanner.engines.recon import SurfaceReconEngine
    from app.scanner.engines.network import NetworkScanEngine
    from app.scanner.engines.os_fingerprint import OSFingerprintEngine
    from app.scanner.engines.tls_engine import TLSCryptoEngine
    from app.scanner.engines.crypto_analysis import CryptoAnalysisEngine
    from app.scanner.engines.cdn_waf import CDNWAFEngine
    from app.scanner.engines.tech_fingerprint import TechFingerprintEngine
    from app.scanner.engines.web_discovery import WebAPIDiscoveryEngine
    from app.scanner.engines.hidden_discovery import HiddenDiscoveryEngine
    from app.scanner.engines.vuln_engine import VulnerabilityEngine
    from app.scanner.engines.correlation import CorrelationRiskEngine
    from app.scanner.engines.reporting import CBOMReportEngine

    db = get_database()
    collection = db[SCANS_COLLECTION]

    await collection.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": ScanStatus.RUNNING.value,
            "started_at": datetime.utcnow(),
            "current_stage": "Initialising custom engine",
            "progress": 0,
        }},
    )

    async def _broadcast(event_name, payload):
        """Pipeline calls broadcast(event_name, payload_dict).
        We wrap it into a WS message and send to the correct scan_id room."""
        msg = {"type": "status", "event": event_name}
        if isinstance(payload, dict):
            msg.update(payload)
        await ws_manager.broadcast(msg, scan_id)

    throttle = AdaptiveRateController()
    ctx = ScanContext(
        scan_id=scan_id,
        domain=request.domain.strip().lower(),
        options={
            "scan_depth": scan_depth,
            "max_subdomains": request.max_subdomains,
            "port_profile": settings.SCANNER_PORT_PROFILE,
            "ai_adaptive": settings.SCANNER_AI_ADAPTIVE,
        },
        throttle=throttle,
        broadcast=_broadcast,
        db=db,
    )

    stages = [
        SurfaceReconEngine(),
        NetworkScanEngine(),
        OSFingerprintEngine(),
        TLSCryptoEngine(),
        CryptoAnalysisEngine(),
        CDNWAFEngine(),
        TechFingerprintEngine(),
        WebAPIDiscoveryEngine(),
        HiddenDiscoveryEngine(),
        VulnerabilityEngine(),
        CorrelationRiskEngine(),
        CBOMReportEngine(),
    ]

    pipeline = PipelineManager(stages=stages)

    try:
        result = await pipeline.run(ctx)

        tls_list = []
        for tp in (ctx.tls_profiles or []):
            tls_list.append(tp if isinstance(tp, dict) else tp)

        update: dict = {
            "status": ScanStatus.COMPLETED.value,
            "completed_at": datetime.utcnow(),
            "progress": 100,
            "current_stage": "Completed",
        }

        # ── Normalize subdomains → assets list ──
        if ctx.subdomains:
            normalized_hosts: list[str] = []
            for sub in ctx.subdomains:
                if isinstance(sub, dict):
                    host = str(sub.get("hostname") or sub.get("subdomain") or "").strip().lower()
                else:
                    host = str(sub).strip().lower()
                if host:
                    normalized_hosts.append(host)

            update["subdomains"] = normalized_hosts
            update["assets"] = [
                {
                    "subdomain": host,
                    "ip": (ctx.ip_map or {}).get(host, [None])[0] if ctx.ip_map else None,
                    "open_ports": [
                        sv.get("port")
                        for sv in (ctx.services or [])
                        if isinstance(sv, dict) and sv.get("host") == host
                    ],
                }
                for host in normalized_hosts
            ]

        # ── Core scan data ──
        if ctx.tls_profiles:
            update["tls_results"] = [t if isinstance(t, dict) else t for t in ctx.tls_profiles]
        if ctx.crypto_findings:
            update["cbom"] = [f if isinstance(f, dict) else f for f in ctx.crypto_findings]
        if ctx.dns_records:
            update["dns_records"] = [r if isinstance(r, dict) else r for r in ctx.dns_records]

        # ── V2 engine fields (previously not saved!) ──
        if ctx.services:
            update["services"] = [s if isinstance(s, dict) else s for s in ctx.services]
        if ctx.os_fingerprints:
            update["os_fingerprints"] = [o if isinstance(o, dict) else o for o in ctx.os_fingerprints]
        if ctx.cdn_waf_intel:
            update["cdn_waf_intel"] = [c if isinstance(c, dict) else c for c in ctx.cdn_waf_intel]
        if ctx.tech_fingerprints:
            update["tech_fingerprints"] = [t if isinstance(t, dict) else t for t in ctx.tech_fingerprints]
        if ctx.web_profiles:
            update["web_profiles"] = [w if isinstance(w, dict) else w for w in ctx.web_profiles]
        if ctx.hidden_findings:
            update["hidden_findings"] = [h if isinstance(h, dict) else h for h in ctx.hidden_findings]
        if ctx.vuln_findings:
            update["vuln_findings"] = [v if isinstance(v, dict) else v for v in ctx.vuln_findings]
        if ctx.all_findings:
            update["all_findings"] = [f if isinstance(f, dict) else f for f in ctx.all_findings]
        if ctx.ip_map:
            update["ip_map"] = ctx.ip_map
        if ctx.whois:
            update["whois"] = ctx.whois
        if ctx.graph:
            update["graph"] = ctx.graph
        if ctx.risk_scores:
            update["risk_scores"] = ctx.risk_scores
        if ctx.estate_tier and ctx.estate_tier != "Unknown":
            update["estate_tier"] = ctx.estate_tier
        if ctx.executive_summary:
            update["executive_summary"] = ctx.executive_summary

        # ── Quantum Risk Scoring via quantum_risk_engine + ML Ensemble ──
        # Convert crypto_findings dicts → CryptoComponent objects for the engine
        _COMPONENT_TO_CATEGORY = {
            "cipher_kex": AlgorithmCategory.KEY_EXCHANGE,
            "cipher_enc": AlgorithmCategory.CIPHER,
            "cipher_mac": AlgorithmCategory.HASH,
            "certificate_key": AlgorithmCategory.SIGNATURE,
            "cert_signature": AlgorithmCategory.HASH,
            "certificate_validity": AlgorithmCategory.SIGNATURE,
            "certificate_trust": AlgorithmCategory.SIGNATURE,
            "protocol": AlgorithmCategory.PROTOCOL,
            "hndl_risk": AlgorithmCategory.KEY_EXCHANGE,
            "crypto_score": AlgorithmCategory.CIPHER,  # composite
        }
        _RISK_TO_QSTATUS = {
            "critical": QuantumStatus.VULNERABLE,
            "high": QuantumStatus.VULNERABLE,
            "medium": QuantumStatus.PARTIALLY_SAFE,
            "low": QuantumStatus.QUANTUM_SAFE,
            "none": QuantumStatus.QUANTUM_SAFE,
            "info": QuantumStatus.QUANTUM_SAFE,
        }

        all_components: list[CryptoComponent] = []
        for fd in (ctx.crypto_findings or []):
            f = fd if isinstance(fd, dict) else {}
            comp_type = f.get("component", "")
            algo = f.get("algorithm", "unknown")
            qr = f.get("quantum_risk", "medium")

            # Skip composite score rows — not real components
            if comp_type == "crypto_score":
                continue

            cat = _COMPONENT_TO_CATEGORY.get(comp_type, AlgorithmCategory.CIPHER)
            qs_status = _RISK_TO_QSTATUS.get(qr, QuantumStatus.VULNERABLE)

            # Extract key_size from algorithm name if present (e.g. "RSA-2048" → 2048)
            key_size = None
            for token in algo.replace("-", " ").split():
                if token.isdigit():
                    key_size = int(token)
                    break

            all_components.append(CryptoComponent(
                name=algo,
                category=cat,
                key_size=key_size,
                usage_context=comp_type,
                risk_level=RiskLevel(qr) if qr in ("critical", "high", "medium", "low", "safe") else RiskLevel.MEDIUM,
                quantum_status=qs_status,
                host=f.get("host"),
                details=f.get("evidence"),
            ))

        # Call the real quantum risk engine
        try:
            q_score_obj = quantum_risk_engine.calculate_score(
                all_components,
                aggregation="estate_weakest",
            )
            q_score_dict = q_score_obj.model_dump(mode="json")
            update["quantum_score"] = q_score_dict
            update["risk_level"] = q_score_dict.get("risk_level", "medium")
            logger.info("[%s] Quantum score: %.1f (%s)", scan_id,
                       q_score_obj.score, q_score_obj.risk_level.value)
        except Exception as qe:
            logger.warning("[%s] Quantum risk engine failed: %s", scan_id, qe)
            # Fallback to the reporting engine's simple score
            q_score = result.get("quantum_score", {})
            if q_score:
                update["quantum_score"] = q_score

        # ── Shadow ML Ensemble Assessment (if available) ──
        try:
            from ml import ml_engine as _ml_eng, ensemble_policy as _ens_pol, feature_builder as _ml_fb
            if _ml_eng is not None and _ens_pol is not None and _ml_fb is not None:
                from ml.ensemble import RuleAssessment as _RA
                from ml.shadow_store import ShadowStore as _SS
                _shadow = _SS(db)
                for _comp in all_components:
                    try:
                        _rule_a = _RA(
                            quantum_status_rule=(_comp.quantum_status.value
                                                 if hasattr(_comp.quantum_status, "value")
                                                 else str(_comp.quantum_status)).upper(),
                            rule_confidence=float(q_score_obj.confidence) if 'q_score_obj' in dir() else 0.65,
                        )
                        _fv = _ml_fb.build(_comp, tls_info=None, rule_assessment={
                            "quantum_status": _rule_a.quantum_status_rule.lower(),
                            "confidence": _rule_a.rule_confidence,
                        })
                        _ml_result = _ml_eng.predict(_fv)
                        _ens_result = _ens_pol.decide(_rule_a, _ml_result, _comp)
                        await _shadow.save(
                            scan_id=scan_id,
                            component_name=_comp.name or "",
                            component_category=(_comp.category.value
                                                if hasattr(_comp.category, "value")
                                                else str(_comp.category)),
                            component_key_size=_comp.key_size,
                            component_host=_comp.host or "",
                            ml_assessment=_ml_result,
                            ensemble_assessment=_ens_result,
                        )
                    except Exception as _ml_comp_exc:
                        logger.debug("ML shadow skip for %s: %s", _comp.name, _ml_comp_exc)
                logger.info("[%s] ML shadow assessments stored for %d components", scan_id, len(all_components))
        except Exception as _ml_exc:
            logger.debug("[%s] ML shadow layer inactive: %s", scan_id, _ml_exc)

        recs = result.get("recommendations", [])
        if recs:
            update["recommendations"] = recs
        if pipeline.metrics:
            update["stage_metrics"] = [m.model_dump() for m in pipeline.metrics]

        await collection.update_one({"scan_id": scan_id}, {"$set": update})

        # ── Broadcast structured intermediate results for LiveScanConsole ──
        # TLS finding cards
        for tp in (ctx.tls_profiles or []):
            p = tp if isinstance(tp, dict) else {}
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "tls_finding",
                "payload": {
                    "host": p.get("host", ""),
                    "port": p.get("port", 443),
                    "tls_versions": p.get("tls_versions_supported", {}),
                    "negotiated_cipher": p.get("negotiated_cipher"),
                    "cert": {
                        "issuer": (p.get("leaf_cert") or {}).get("issuer", ""),
                        "subject": (p.get("leaf_cert") or {}).get("subject", ""),
                        "valid_to": (p.get("leaf_cert") or {}).get("valid_to", ""),
                        "key_type": (p.get("leaf_cert") or {}).get("key_type", ""),
                        "key_size": (p.get("leaf_cert") or {}).get("key_size"),
                    } if p.get("leaf_cert") else None,
                    "pqc_signals": p.get("pqc_signals", []),
                    "forward_secrecy": p.get("forward_secrecy", False),
                    "ciphers_count": len(p.get("accepted_ciphers") or []),
                },
            }, scan_id)

        # Crypto summary card
        if ctx.crypto_findings:
            categories = {}
            vulnerable = []
            for f in ctx.crypto_findings:
                fd = f if isinstance(f, dict) else {}
                comp = fd.get("component", "unknown")
                categories[comp] = categories.get(comp, 0) + 1
                if fd.get("quantum_risk") in ("critical", "high"):
                    vulnerable.append(fd.get("algorithm", "unknown"))
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "crypto_summary",
                "payload": {
                    "total_components": len(ctx.crypto_findings),
                    "by_category": categories,
                    "vulnerable_count": len(vulnerable),
                    "vulnerable_algorithms": list(set(vulnerable))[:10],
                },
            }, scan_id)

        # Quantum score card
        if update.get("quantum_score"):
            qs = update["quantum_score"]
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "quantum_score",
                "payload": {
                    "score": qs.get("score", 0),
                    "risk_level": qs.get("risk_level", "unknown"),
                    "confidence": qs.get("confidence", 0),
                },
            }, scan_id)

        # CBOM summary card
        cbom_data = result.get("cbom") or ctx.cbom or {}
        if cbom_data:
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "cbom_summary",
                "payload": {
                    "domain": ctx.domain,
                    "total_components": cbom_data.get("total_components", 0),
                    "quantum_safe_count": cbom_data.get("quantum_safe_count", 0),
                    "weak_crypto_count": cbom_data.get("weak_crypto_count", 0),
                },
            }, scan_id)

        await ws_manager.broadcast({
            "type": "status",
            "status": "completed",
            "message": "Custom engine scan completed.",
        }, scan_id)

        logger.info("[%s] Custom engine scan completed.", scan_id)

    except Exception as exc:
        logger.exception("[%s] Custom engine pipeline failed: %s", scan_id, exc)
        err = str(exc)[:500]
        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": ScanStatus.FAILED.value,
                "error": err,
                "completed_at": datetime.utcnow(),
            }},
        )
        await ws_manager.broadcast({"type": "status", "status": "failed", "message": err}, scan_id)


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
      7. HTTP security headers, asset bucketing (classification probes), optional Nuclei
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

        disc_token = None
        if request.execution_time_limit_seconds is not None:
            disc_token = asset_discovery.set_discovery_tool_timeout(
                request.execution_time_limit_seconds
            )
        try:
            assets = await asset_discovery.discover_assets(
                request.domain,
                ports=request.ports,
                broadcast_func=broadcast_tool_log,
                max_subdomains_cap=request.max_subdomains,
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
        finally:
            if disc_token is not None:
                asset_discovery.reset_discovery_tool_timeout(disc_token)

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

        web_count = sum(1 for a in assets if classify_asset_service(getattr(a, "services", [])) == "web_app")
        api_count = sum(1 for a in assets if classify_asset_service(getattr(a, "services", [])) == "api")
        srv_count = len(assets) - web_count - api_count

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
        tls_exec = request.execution_time_limit_seconds
        for asset in assets:
            for port in asset.open_ports:
                tls_tasks.append(
                    tls_scanner.scan_tls(
                        asset.subdomain,
                        port,
                        execution_time_limit_seconds=tls_exec,
                    )
                )

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
        def _tls_row_confidence(raw: Any) -> float:
            if raw is None:
                return 0.65
            s = str(raw).strip().lower()
            return {"high": 0.9, "medium": 0.7, "low": 0.5}.get(s, 0.65)

        def _row_confidence_value(row: Any) -> Any:
            if isinstance(row, dict):
                return row.get("confidence")
            return getattr(row, "confidence", None)

        tls_conf_levels = [_tls_row_confidence(_row_confidence_value(t)) for t in tls_results]
        agg_raw = (getattr(settings, "QUANTUM_SCORE_AGGREGATION", None) or "estate_weakest").strip().lower()
        if agg_raw not in ("estate_weakest", "per_host_min", "p25"):
            agg_raw = "estate_weakest"
        q_score = quantum_risk_engine.calculate_score(
            all_components,
            aggregation=agg_raw,  # type: ignore[arg-type]
            tls_scan_confidences=tls_conf_levels,
        )

        is_high_risk = 1 if q_score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] else 0

        # ── Shadow ML assessment (never changes user-facing quantum_status) ──
        try:
            from ml import ml_engine as _ml_eng, ensemble_policy as _ens_pol, feature_builder as _ml_fb
            if _ml_eng is not None and _ens_pol is not None and _ml_fb is not None:
                from ml.ensemble import RuleAssessment as _RA
                from ml.shadow_store import ShadowStore as _SS
                _shadow = _SS(collection.database)
                _tls_map = {t.host: t for t in tls_results if hasattr(t, "host")}
                for _comp in all_components:
                    try:
                        _tls_ctx = _tls_map.get(_comp.host)
                        _rule_a = _RA(
                            quantum_status_rule=(_comp.quantum_status.value
                                                 if hasattr(_comp.quantum_status, "value")
                                                 else str(_comp.quantum_status)).upper(),
                            rule_confidence=float(q_score.confidence),
                        )
                        _fv = _ml_fb.build(_comp, tls_info=_tls_ctx, rule_assessment={
                            "quantum_status": _rule_a.quantum_status_rule.lower(),
                            "confidence": _rule_a.rule_confidence,
                        })
                        _ml_result = _ml_eng.predict(_fv)
                        _ens_result = _ens_pol.decide(_rule_a, _ml_result, _comp)
                        await _shadow.save(
                            scan_id=scan_id,
                            component_name=_comp.name or "",
                            component_category=(_comp.category.value
                                                if hasattr(_comp.category, "value")
                                                else str(_comp.category)),
                            component_key_size=_comp.key_size,
                            component_host=_comp.host or "",
                            ml_assessment=_ml_result,
                            ensemble_assessment=_ens_result,
                        )
                    except Exception as _ml_comp_exc:
                        logger.debug("ML shadow skip for %s: %s", _comp.name, _ml_comp_exc)
                logger.info("[%s] ML shadow assessments stored for %d components", scan_id, len(all_components))
        except Exception as _ml_exc:
            logger.debug("ML shadow layer inactive: %s", _ml_exc)

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

        # ── Stage 7: HTTP Security Headers + asset bucketing + optional Nuclei ──
        logger.info("[%s] Stage 7/8: HTTP Security Headers", scan_id)
        headers_tasks = [scan_headers(asset.subdomain) for asset in assets]
        headers_results = await asyncio.gather(*headers_tasks, return_exceptions=True)
        headers_results = [r for r in headers_results if not isinstance(r, Exception)]

        logger.info("[%s] Asset classification (bucketing)", scan_id)
        try:
            assets = await enrich_discovered_assets(
                assets,
                tls_results,
                headers_results,
                request.domain,
            )
        except Exception as cls_exc:
            logger.warning("[%s] Asset classification failed (continuing): %s", scan_id, cls_exc)

        vuln_findings = await run_nuclei_scan(assets, request.execution_time_limit_seconds)

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "headers_results": [h.model_dump(mode="json") for h in headers_results],
                "assets": [a.model_dump(mode="json") for a in assets],
                "vuln_findings": [v.model_dump(mode="json") for v in vuln_findings],
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
                "cve_findings": [c.model_dump(mode="json") for c in cve_findings],
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


@router.post(
    "/scan/{scan_id}/cancel",
    summary="Cancel a running or pending scan",
)
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
        
    scans = await db[SCANS_COLLECTION].find(query, sort=[("completed_at", -1)]).to_list(length=5)

    if not scans:
        return []
        
    # Standardize output for the table + Phase 3 threat ↔ NIST enrichment
    all_components = []
    seen = set()
    for doc in scans:
        cbom_report = doc.get("cbom_report") or {}
        components = cbom_report.get("components")
        
        # Fallback to raw cbom array if report was not generated
        if not components:
            components = doc.get("cbom", [])
        for c in components:
            c_dict = dict(c)
            domain_val = doc.get("domain", "")
            
            # Deduplicate
            sig = (domain_val, c_dict.get("name"), c_dict.get("category"), c_dict.get("key_size"))
            if sig in seen:
                continue
            seen.add(sig)
            
            enriched = enrich_cbom_component_dict(c_dict)
            enriched["domain"] = domain_val
            all_components.append(enriched)
        
    return all_components

def _normalize_negotiated_tls_label(raw: str | None) -> str:
    """Bucket negotiated tls_version for distribution (one count per TLS endpoint row)."""
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


def _encryption_protocol_sort_key(name: str) -> tuple:
    order = {
        "TLSv1.3": 0,
        "TLSv1.2": 1,
        "TLSv1.1": 2,
        "TLSv1.0": 3,
        "Unknown": 99,
    }
    return (order.get(name, 50), name)


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
    negotiated_tls: dict = {}
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
        
        # CAs from tls_results — normalize issuer DN to real-world CA names for charts
        for t in scan.get("tls_results", []):
            raw_iss = extract_issuer_raw_from_tls_row(t)
            ca = normalize_ca_display_name(raw_iss)
            cas[ca] = cas.get(ca, 0) + 1
            # Negotiated protocol per endpoint — avoids "one count per supported proto" flat bars
            if not t.get("error"):
                bucket = _normalize_negotiated_tls_label(t.get("tls_version"))
                negotiated_tls[bucket] = negotiated_tls.get(bucket, 0) + 1

    if negotiated_tls:
        enc_rows = sorted(
            [{"name": k, "value": v} for k, v in negotiated_tls.items()],
            key=lambda row: _encryption_protocol_sort_key(row["name"]),
        )
    else:
        enc_rows = sorted(
            [{"name": k, "value": v} for k, v in tls_versions.items()],
            key=lambda row: _encryption_protocol_sort_key(row["name"]),
        )

    ca_chart = sorted(
        [{"name": k, "value": v} for k, v in cas.items()],
        key=lambda r: (-int(r["value"]), str(r["name"]).lower()),
    )

    return {
        "key_length_distribution": [{"name": k, "count": v} for k, v in key_lengths.items()],
        "top_certificate_authorities": ca_chart,
        "encryption_protocols": enc_rows,
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


@router.get(
    "/security-roadmap/{domain}",
    summary="Security roadmap: at-risk algorithms & TLS posture → target solutions",
    tags=["Scanner"],
)
async def get_security_roadmap(domain: str):
    """
    Builds a read-only roadmap from the latest completed scan for the domain:
    PQC migration recommendations (from CBOM/crypto analysis) plus aggregated TLS/cert rows.
    """
    db = get_database()
    d = domain.strip().lower()
    doc = await db[SCANS_COLLECTION].find_one(
        {"domain": d, "status": ScanStatus.COMPLETED.value},
        sort=[("completed_at", -1), ("started_at", -1)],
    )
    if not doc:
        doc = await db[SCANS_COLLECTION].find_one(
            {"domain": d},
            sort=[("started_at", -1)],
        )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for domain: {domain}",
        )
    items = build_security_roadmap(doc)
    q = doc.get("quantum_score") or {}
    return {
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "scan_status": doc.get("status"),
        "completed_at": doc.get("completed_at"),
        "quantum_risk_level": q.get("risk_level"),
        "quantum_score": q.get("score"),
        "items": items,
        "disclaimer": (
            "Indicative guidance derived from external scan signals; validate with architecture, "
            "application, and PKI owners before production or compliance commitments."
        ),
    }


@router.get(
    "/security-roadmap/latest",
    summary="Security roadmap: latest completed scan (no domain input)",
    tags=["Scanner"],
)
async def get_security_roadmap_latest():
    """
    Roadmap fallback when the UI doesn't have a stored domain.
    Uses the latest completed scan found in MongoDB.
    """
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one(
        {"status": ScanStatus.COMPLETED.value},
        sort=[("completed_at", -1), ("started_at", -1)],
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No completed scan results found yet.",
        )
    items = build_security_roadmap(doc)
    q = doc.get("quantum_score") or {}
    return {
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "scan_status": doc.get("status"),
        "completed_at": doc.get("completed_at"),
        "quantum_risk_level": q.get("risk_level"),
        "quantum_score": q.get("score"),
        "items": items,
        "disclaimer": (
            "Indicative guidance derived from external scan signals; validate with architecture, "
            "application, and PKI owners before production or compliance commitments."
        ),
    }


@router.get(
    "/security-roadmap/scan/{scan_id}",
    summary="Security roadmap: by scan_id (historical scans)",
    tags=["Scanner"],
)
async def get_security_roadmap_by_scan_id(scan_id: str):
    """
    Load a roadmap for a specific historical scan (completed scans recommended).
    This enables the UI to browse previous scans without typing a domain.
    """
    sid = (scan_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="scan_id is required")
    db = get_database()
    doc = await db[SCANS_COLLECTION].find_one({"scan_id": sid})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    items = build_security_roadmap(doc)
    q = doc.get("quantum_score") or {}
    return {
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "scan_status": doc.get("status"),
        "completed_at": doc.get("completed_at"),
        "quantum_risk_level": q.get("risk_level"),
        "quantum_score": q.get("score"),
        "items": items,
        "disclaimer": (
            "Indicative guidance derived from external scan signals; validate with architecture, "
            "application, and PKI owners before production or compliance commitments."
        ),
    }


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
            cat = classify_asset_service(a.get("services") or [])
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


@router.get("/assets/distribution", summary="Get asset type distribution", tags=["Assets"])
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
async def get_crypto_security(domain: Optional[str] = None):
    db = get_database()
    query: Dict[str, Any] = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scans = await db[SCANS_COLLECTION].find(
        query, sort=[("completed_at", -1)]
    ).to_list(length=5)

    results_dict = {}
    
    for scan in scans:
        cbom_report = scan.get("cbom_report") or {}
        components = cbom_report.get("components") or scan.get("cbom", [])
        ml_pqc_map = {}
        for c in components:
            if c.get("category") == "cipher" and c.get("name"):
                ml_pqc_map[c.get("name")] = c.get("quantum_status", "").replace("_", "-")
                
        host_services: dict[str, list[dict]] = {}
        for svc in (scan.get("services") or []):
            h = (svc.get("host") or "").lower()
            if h:
                host_services.setdefault(h, []).append(svc)
        
        for t in scan.get("tls_results", []):
            host = (t.get("host") or scan.get("domain", "")).lower()
            port = t.get("port", 443)
            key = f"{host}:{port}"
            
            asset_slug = classify_asset_service(services=host_services.get(host))
            raw_iss = extract_issuer_raw_from_tls_row(t)
            cert = t.get("certificate") or {}
            
            # Extract fields
            tls_version = t.get("tls_version", "")
            cipher_suite = t.get("cipher_suite", "")
            key_length_val = str(t.get('cipher_bits') or "")
            key_exchange = t.get("key_exchange", "")
            if key_exchange == "UNKNOWN":
                if cipher_suite.startswith("TLS_AES") or cipher_suite.startswith("TLS_CHACHA20"):
                    key_exchange = "TLSv1.3 Default"
                else:
                    key_exchange = "Unknown"
            elif not key_exchange:
                key_exchange = "Unknown"
            ca_val = normalize_ca_display_name(raw_iss)
            cert_expiry_val = cert.get("days_until_expiry")
            
            if key not in results_dict:
                results_dict[key] = {
                    "asset": t.get("host", scan.get("domain", "")),
                    "port": port,
                    "key_length": key_length_val,
                    "cipher_suite": cipher_suite,
                    "tls_version": tls_version,
                    "key_exchange": key_exchange,
                    "certificate_authority": ca_val,
                    "cert_expiry": f"{cert_expiry_val} days" if cert_expiry_val is not None else "—",
                    "pqcStatus": ml_pqc_map.get(cipher_suite, ""),
                    "asset_type": asset_type_label(asset_slug),
                }
            else:
                # Merge missing fields from older scans if current is incomplete
                existing = results_dict[key]
                if not existing["pqcStatus"] and ml_pqc_map.get(cipher_suite):
                    existing["pqcStatus"] = ml_pqc_map.get(cipher_suite)
                if not existing["tls_version"] and tls_version:
                    existing["tls_version"] = tls_version
                if not existing["cipher_suite"] and cipher_suite:
                    existing["cipher_suite"] = cipher_suite
                if not existing["key_length"] and key_length_val:
                    existing["key_length"] = key_length_val
                if not existing["key_exchange"] and key_exchange:
                    existing["key_exchange"] = key_exchange
                if existing["certificate_authority"] == "Unknown" and ca_val != "Unknown":
                    existing["certificate_authority"] = ca_val
                if existing["cert_expiry"] == "—" and cert_expiry_val is not None:
                    existing["cert_expiry"] = f"{cert_expiry_val} days"

    return list(results_dict.values())


@router.get(
    "/crypto/scan-findings",
    summary="TLS/CVE mapping vs optional active-scan findings (latest completed scan)",
    tags=["Crypto"],
)
async def get_crypto_scan_findings(domain: Optional[str] = None):
    """CVE findings from crypto pipeline vs Nuclei-style `vuln_findings` when enabled."""
    db = get_database()
    query: dict = {"status": "completed"}
    if domain:
        d = domain.strip()
        query["domain"] = {"$regex": f"^{re.escape(d)}$", "$options": "i"}
    doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        return {
            "domain": None,
            "scan_id": None,
            "cve_findings": [],
            "vuln_findings": [],
        }
    return {
        "domain": doc.get("domain"),
        "scan_id": doc.get("scan_id"),
        "cve_findings": doc.get("cve_findings") or [],
        "vuln_findings": doc.get("vuln_findings") or [],
    }


# ════════════════════════════════════════════════════════════════════
# PQC Posture endpoints
# ════════════════════════════════════════════════════════════════════

@router.get("/pqc/posture", summary="Get PQC posture overview", tags=["PQC"])
async def get_pqc_posture(domain: Optional[str] = None):
    db = get_database()
    query: Dict[str, Any] = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scan = await db[SCANS_COLLECTION].find_one(
        query, sort=[("completed_at", -1)]
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
            "quantum_readiness": None,
        }

    tls_results = scan.get("tls_profiles", []) or scan.get("tls_results", []) or []
    assets = scan.get("assets", []) or []
    tls_map = {t.get("host"): t for t in tls_results if isinstance(t, dict) and t.get("host")}

    # Some scan runs may not persist asset_discovery output (assets=[]), but still have tls_results.
    # Derive a host list from tls_results as fallback, and tolerate different asset key names.
    hosts: list[str] = []
    if assets:
        for a in assets:
            if not isinstance(a, dict):
                continue
            h = (a.get("subdomain") or a.get("host") or a.get("asset") or a.get("name") or "").strip()
            if h:
                hosts.append(h)
    else:
        for t in tls_results:
            if not isinstance(t, dict): continue
            h = (t.get("host") or "").strip()
            if h:
                hosts.append(h)

    # Deduplicate while preserving order
    _seen = set()
    hosts = [h for h in hosts if not (h.lower() in _seen or _seen.add(h.lower()))]
    
    asset_pqc_status = []
    elite_pqc_count = 0
    standard_count = 0
    legacy_count = 0
    critical_count = 0

    pqc_kem_endpoints = 0
    tls_modern_endpoints = 0

    for host in hosts:
        tls = tls_map.get(host, {})
        
        # Support both V1 (tls_version, pqc_kem_observed) and V2 (tls_versions_supported, pqc_signals)
        pqc_signals = tls.get("pqc_signals", [])
        pqc_signal_hints = tls.get("pqc_signal_hints") or []
        if pqc_signals:
            pqc_signal_hints.extend(pqc_signals)
            
        pq_signal = bool(tls.get("pqc_kem_observed") or tls.get("hybrid_key_exchange") or pqc_signals)
        
        supported_versions = tls.get("tls_versions_supported", {})
        if supported_versions:
            tls_mod = bool(supported_versions.get("TLSv1_3"))
            if supported_versions.get("TLSv1_3"):
                tv = "TLSv1.3"
            elif supported_versions.get("TLSv1_2"):
                tv = "TLSv1.2"
            elif supported_versions.get("TLSv1_1"):
                tv = "TLSv1.1"
            elif supported_versions.get("TLSv1"):
                tv = "TLSv1"
            else:
                tv = "Unknown"
        else:
            tv = str(tls.get("tls_version") or "")
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
            "pqc_signal_hints": pqc_signal_hints[:8],
            "tls_version": tv or "Unknown",
            "risk": "Low" if is_ready else "High",
            "status": (
                "PQC / hybrid signal"
                if pq_signal
                else ("TLS 1.3 (modern)" if tls_mod else "Migration Required")
            ),
            "score": 950 if pq_signal else 850 if tls_mod else 450 if grade == "Standard" else 250,
        })

    total = len(hosts) or 1
    qs = scan.get("quantum_score") or {}
    q_break = qs.get("breakdown") if isinstance(qs.get("breakdown"), dict) else {}
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
        "quantum_readiness": {
            "score": qs.get("score"),
            "risk_level": qs.get("risk_level"),
            "confidence": qs.get("confidence"),
            "catalog_version": qs.get("catalog_version"),
            "aggregation": qs.get("aggregation"),
            "drivers": (qs.get("drivers") or [])[:5],
            "breakdown": {
                "key_exchange": q_break.get("key_exchange_score"),
                "signature": q_break.get("signature_score"),
                "cipher": q_break.get("cipher_score"),
                "protocol": q_break.get("protocol_score"),
                "hash": q_break.get("hash_score"),
            },
        },
    }



@router.get("/pqc/vulnerable-algorithms", summary="Get vulnerable algorithms list", tags=["PQC"])
async def get_vulnerable_algorithms(domain: Optional[str] = None):
    db = get_database()
    query: Dict[str, Any] = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scan = await db[SCANS_COLLECTION].find_one(
        query, sort=[("completed_at", -1)]
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

def _build_cyber_rating_payload(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Build 0-1000 cyber rating payload from a completed scan document."""
    # Scale 0-100 to 0-1000
    qscore = scan.get("quantum_score") if isinstance(scan, dict) else {}
    raw_score = (qscore or {}).get("score", 75) if isinstance(qscore, dict) else 75
    try:
        normalized_score = float(raw_score) if raw_score is not None else 75.0
    except (TypeError, ValueError):
        normalized_score = 75.0
    score_1000 = int(normalized_score * 10)
    score_1000 = max(0, min(1000, score_1000))
    tier = "Elite-PQC" if score_1000 > 700 else "Standard" if score_1000 >= 400 else "Legacy"

    # Explainability: derive a small evidence summary from tls_results.
    # This is intentionally heuristic and only intended to justify the tier to users.
    tls_results = scan.get("tls_results", []) or []

    legacy_ver = {"TLSv1.0", "TLSv1.1", "TLSv1", "SSLv3", "SSLv2"}
    weak_tokens = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "TLS 1.0", "TLS 1.1"]
    pqc_tokens = ["KYBER", "DILITHIUM", "FALCON", "SPHINCS", "ML-KEM", "MLKEM", "ML_KEM", "ML-DSA"]

    def _tls_ver_raw(t: dict) -> str:
        return str(t.get("tls_version") or "").strip()

    def _tls_ver(t: dict) -> str:
        """Normalize scanner variants (e.g. 'TLS 1.1', 'TLSv1.1', 'TLS11') for explainability counts."""
        raw = _tls_ver_raw(t).upper().replace(" ", "")
        if raw.startswith("SSL") or "SSLV2" in raw or "SSLV3" in raw:
            return _tls_ver_raw(t).strip() or "SSLv3"
        if "1.3" in raw or "TLSV1.3" in raw or raw.endswith("TLS13"):
            return "TLSv1.3"
        if "TLSV1.2" in raw or ("1.2" in raw and "1.3" not in raw):
            return "TLSv1.2"
        if "TLSV1.1" in raw or "TLS11" in raw or ("1.1" in raw and "1.2" not in raw and "1.3" not in raw):
            return "TLSv1.1"
        if "TLSV1.0" in raw or raw == "TLSV1" or ("1.0" in raw and "1.1" not in raw and "1.2" not in raw):
            return "TLSv1.0"
        return _tls_ver_raw(t)

    def _cipher(t: dict) -> str:
        return str(t.get("cipher_suite") or "").upper()

    def _is_weak_indicator(t: dict) -> bool:
        tls = _tls_ver_raw(t).upper()
        cipher = _cipher(t)
        return any(tok in cipher for tok in weak_tokens) or any(tok in tls for tok in weak_tokens)

    def _is_legacy_tls(t: dict) -> bool:
        tls = _tls_ver(t)
        return tls in legacy_ver or tls.startswith("SSL")

    def _is_hndl_risk(t: dict) -> bool:
        tls = _tls_ver(t)
        cipher = _cipher(t)
        is_weak = _is_weak_indicator(t)
        is_pqc_safe = any(tok in cipher for tok in pqc_tokens)

        # Avoid over-flagging TLS 1.3 endpoints for HNDL solely due to RSA mentions.
        # If TLS 1.3 with no weak indicators is observed, we treat HNDL risk as not inferred.
        if "1.3" in tls and not is_weak:
            return False

        tls_low = tls.lower()
        if is_pqc_safe:
            return False

        return (
            ("1.0" in tls_low)
            or ("1.1" in tls_low)
            or ("1.2" in tls_low)
            or ("ssl" in tls_low)
        ) and ("rsa" in cipher.lower() or "dh" in cipher.lower())

    tls_total = len(tls_results)
    tls_1_3 = sum(1 for t in tls_results if _tls_ver(t) == "TLSv1.3" or _tls_ver(t).endswith("1.3"))
    tls_1_2 = sum(1 for t in tls_results if _tls_ver(t) == "TLSv1.2" or _tls_ver(t).endswith("1.2"))
    legacy_count = sum(1 for t in tls_results if _is_legacy_tls(t))
    weak_cipher_count = sum(1 for t in tls_results if _is_weak_indicator(t))
    hndl_risk_count = sum(1 for t in tls_results if _is_hndl_risk(t))

    drivers: List[str] = []
    qs_explain = scan.get("quantum_score") or {}
    q_drv = qs_explain.get("drivers") if isinstance(qs_explain.get("drivers"), list) else []
    for d in q_drv[:3]:
        if isinstance(d, str) and d.strip():
            drivers.append(d.strip())
    if tls_total:
        drivers.append(f"TLSv1.3 endpoints: {tls_1_3}/{tls_total}")
        if legacy_count:
            drivers.append(f"Legacy TLS endpoints: {legacy_count}")
        if weak_cipher_count:
            drivers.append(f"Weak/obsolete cipher indicators: {weak_cipher_count}")
        if hndl_risk_count:
            drivers.append(f"HNDL risk inferred (heuristic): {hndl_risk_count}")
    else:
        drivers.append("No TLS evidence rows found for this scan.")
    
    # Per-URL scores
    per_url = []
    tls_results = scan.get("tls_results", [])
    for t in tls_results[:8]:
        url_score = int(normalized_score * 10)
        tv = _tls_ver(t)
        if tv == "TLSv1.3":
            url_score += 50
        elif tv in ("TLSv1.0", "TLSv1.1"):
            url_score -= 200
        per_url.append({
            "url": t.get("host") or t.get("subdomain") or "unknown",
            "score": max(0, min(1000, url_score))
        })

    return {
        "scan_id": scan.get("scan_id"),
        "domain": scan.get("domain"),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "score": score_1000,
        "max_score": 1000,
        "tier": tier,
        "tier_description": f"Overall {tier} security posture",
        "explain": {
            "score": score_1000,
            "tier": tier,
            "quantum_confidence": qs_explain.get("confidence"),
            "quantum_catalog_version": qs_explain.get("catalog_version"),
            "evidence": {
                "tls_total": tls_total,
                "tls_1_3": tls_1_3,
                "tls_1_2": tls_1_2,
                "legacy_tls": legacy_count,
                "weak_cipher_indicators": weak_cipher_count,
                "hndl_risk_inferred": hndl_risk_count,
            },
            "drivers": drivers,
            "note": "Explainability merges quantum engine drivers (CBOM) with tls_results heuristics; validate with PKI and engineering owners.",
        },
        "tiers": [
            {"status": "Legacy",    "range": "< 400"},
            {"status": "Standard",  "range": "400 till 700"},
            {"status": "Elite-PQC", "range": "> 700"},
        ],
        "per_url_scores": per_url,
    }


@router.get("/cyber-rating", summary="Get enterprise cyber rating", tags=["Cyber Rating"])
async def get_cyber_rating(domain: Optional[str] = None):
    db = get_database()
    query: Dict[str, Any] = {"status": "completed"}
    if domain:
        query["domain"] = domain
    scan = await db[SCANS_COLLECTION].find_one(
        query, sort=[("completed_at", -1)]
    )
    if not scan:
        return {"score": 0, "max_score": 1000, "tier": "N/A", "per_url_scores": []}
    return _build_cyber_rating_payload(scan)


@router.get("/cyber-rating/history", summary="Get cyber rating history across domains", tags=["Cyber Rating"])
async def get_cyber_rating_history(limit: int = 200, domain: Optional[str] = None):
    db = get_database()
    lim = min(max(limit, 1), 1000)
    q: Dict[str, Any] = {"status": "completed"}
    if domain:
        q["domain"] = domain.strip().lower()

    cursor = (
        db[SCANS_COLLECTION]
        .find(q)
        .sort([("completed_at", -1), ("started_at", -1)])
        .limit(lim)
    )

    history: List[Dict[str, Any]] = []
    async for doc in cursor:
        history.append(_build_cyber_rating_payload(doc))

    return {
        "count": len(history),
        "domain_filter": q.get("domain"),
        "history": history,
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
    return {
        "domain": scan.get("domain"),
        "baseline_score_100": sim["baseline_score"],
        "projected_score_100": sim["projected_score"],
        "delta": sim["delta"],
        "assumptions": sim["assumptions"],
        "note": sim["note"],
        "catalog_version": sim.get("catalog_version") or "",
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
# Scheduled reports + mail log (Admin)
# ════════════════════════════════════════════════════════════════════


@router.get("/admin/report-schedules", summary="List scheduled report jobs", tags=["Admin"])
async def list_report_schedules(_admin: User = Depends(require_admin)):
    db = get_database()
    cursor = db[REPORT_SCHEDULES_COLLECTION].find().sort("created_at", -1).limit(100)
    items: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        items.append(row)
    return {"count": len(items), "schedules": items}


@router.post("/admin/report-schedules", summary="Create scheduled report", tags=["Admin"])
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


@router.patch("/admin/report-schedules/{schedule_id}", summary="Update scheduled report", tags=["Admin"])
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


@router.delete("/admin/report-schedules/{schedule_id}", summary="Delete scheduled report", tags=["Admin"])
async def delete_report_schedule(schedule_id: str, _admin: User = Depends(require_admin)):
    db = get_database()
    r = await db[REPORT_SCHEDULES_COLLECTION].delete_one({"schedule_id": schedule_id})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"ok": True}


@router.post(
    "/admin/report-schedules/{schedule_id}/run-now",
    summary="Run scheduled report immediately",
    tags=["Admin"],
)
async def run_report_schedule_now(schedule_id: str, _admin: User = Depends(require_admin)):
    db = get_database()
    sched = await db[REPORT_SCHEDULES_COLLECTION].find_one({"schedule_id": schedule_id})
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await execute_schedule_run(sched, manual=True)
    return {"ok": True}


@router.get("/admin/mail-log", summary="Outbound mail log (SMTP)", tags=["Admin"])
async def get_mail_log(limit: int = 50, _admin: User = Depends(require_admin)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[MAIL_LOG_COLLECTION].find().sort("created_at", -1).limit(lim)
    rows: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        rows.append(row)
    return {"count": len(rows), "events": rows}


@router.get("/admin/report-artifacts", summary="Generated report files (download)", tags=["Admin"])
async def list_report_artifacts(limit: int = 50, _user: User = Depends(get_current_user)):
    lim = min(max(limit, 1), 200)
    db = get_database()
    cursor = db[REPORT_ARTIFACTS_COLLECTION].find().sort("created_at", -1).limit(lim)
    rows: List[dict] = []
    async for row in cursor:
        row.pop("_id", None)
        rows.append(row)
    return {"count": len(rows), "artifacts": rows}


@router.get(
    "/admin/report-artifacts/{artifact_id}/download",
    summary="Download generated report JSON",
    tags=["Admin"],
)
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


# ════════════════════════════════════════════════════════════════════
# AI — Roadmap planner + Copilot (LM Studio compatible)
# ════════════════════════════════════════════════════════════════════


@router.post("/ai/roadmap/plan", summary="AI-assisted migration plan (grounded)", tags=["AI"])
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

    items = build_security_roadmap(doc)[:80]
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


@router.post("/ai/copilot/chat", summary="QuantumShield-only copilot", tags=["AI"])
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


# ════════════════════════════════════════════════════════════════════
# In-app notifications (employee → admin)
# ════════════════════════════════════════════════════════════════════


def _notification_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: doc[k] for k in doc if k != "_id"}
    return out


@router.post(
    "/notifications",
    summary="Send a message to administrators (employees only)",
    tags=["Notifications"],
)
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


@router.get(
    "/notifications/me",
    summary="List notifications you have sent",
    tags=["Notifications"],
)
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


@router.get(
    "/admin/notifications",
    summary="List inbound employee notifications (admin)",
    tags=["Admin"],
)
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


@router.patch(
    "/admin/notifications/{notification_id}",
    summary="Mark a notification as read",
    tags=["Admin"],
)
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





# ════════════════════════════════════════════════════════════════════
# Auth endpoint (demo / fallback)
# ════════════════════════════════════════════════════════════════════

from pydantic import BaseModel

class LoginPayload(BaseModel):
    username: str = ""
    email: str = ""
    password: str = ""

def _get_otp_html(otp: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }}
            .header {{ background-color: #2563eb; padding: 20px; text-align: center; color: white; }}
            .header h1 {{ margin: 0; font-size: 24px; letter-spacing: 1px; color: #ffffff; }}
            .content {{ padding: 40px 30px; text-align: center; color: #333333; }}
            .content p {{ font-size: 16px; line-height: 1.5; color: #555555; }}
            .otp-box {{ margin: 30px auto; padding: 15px 30px; background-color: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 8px; display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #1e293b; }}
            .footer {{ background-color: #f8fafc; padding: 15px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="color: white; margin: 0;">QSCAS Security</h1>
            </div>
            <div class="content">
                <h2>Your Verification Code</h2>
                <p>Please use the following 6-digit code to securely log in to your account. This code will expire in exactly <strong>1 minute</strong>.</p>
                <div class="otp-box">{otp}</div>
                <p>If you did not request this login, please ignore this email.</p>
            </div>
            <div class="footer">
                &copy; 2026 QuantumShield System. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

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

    demo_admin_email = "yaswanthavula879@gmail.com"
    demo_employee_email = "employee@example.com"
    demo_password = "pass123"

    email_norm = (payload.email or "").strip().lower()
    user_norm = (payload.username or "").strip().lower()
    pwd = (payload.password or "").strip()

    identity_admin_ok = (
        email_norm == demo_admin_email
        or user_norm == demo_admin_email
        or user_norm == "scanner"
        or user_norm == "admin"
    )
    identity_employee_ok = (
        email_norm == demo_employee_email
        or user_norm == demo_employee_email
        or user_norm == "employee"
    )

    if pwd == demo_password and identity_admin_ok:
        import random
        from datetime import datetime, timedelta
        import smtplib
        from email.mime.text import MIMEText
        
        otp = str(random.randint(100000, 999999))
        
        # Store in global OTP store with 1-minute expiration
        global _otp_store
        if '_otp_store' not in globals():
            _otp_store = {}
        _otp_store[demo_admin_email] = {
            "code": otp,
            "expires_at": datetime.now() + timedelta(minutes=1)
        }
        
        print(f"\n\n{'='*50}")
        print(f"📧 SENDING EMAIL TO: {demo_admin_email}")
        print(f"🔐 YOUR QSCAS VERIFICATION OTP IS: {otp}")
        print(f"{'='*50}\n\n")

        # Real SMTP sending logic
        try:
            sender_email = "abdulyunus295@gmail.com" # TODO: Change to your sender email
            sender_password = "xiln ujts eqra krol" # TODO: Provide your Google App Password
            
            html_content = _get_otp_html(otp)
            msg = MIMEText(html_content, "html")
            msg["Subject"] = "QSCAS Login Verification Code"
            msg["From"] = sender_email
            msg["To"] = demo_admin_email

            # Try to connect (Will fail if app password is not provided, but won't crash backend)
            server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            print("✅ Email sent successfully via SMTP!")
        except Exception as e:
            print(f"⚠️ SMTP failed (did you set up your App Password?): {e}")

        return {
            "requires_otp": True,
            "email": demo_admin_email,
            "message": "OTP sent to email (Valid for 1 min)"
        }

    if pwd == demo_password and identity_employee_ok:
        token_id = uuid.uuid4().hex[:8]
        return {
            "access_token": f"demo-token-employee-{token_id}",
            "token_type": "bearer",
            "role": "Employee",
            "user": {
                "id": token_id,
                "username": "employee",
                "email": demo_employee_email,
                "full_name": "Employee Operator",
                "role": "Employee",
                "is_active": True,
            },
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )

class OTPPayload(BaseModel):
    email: str
    otp: str

@router.post("/auth/verify-otp", summary="Verify OTP and complete login", tags=["Auth"])
async def verify_otp(payload: OTPPayload):
    from datetime import datetime
    email = payload.email.strip().lower()
    provided_otp = payload.otp.strip()
    
    global _otp_store
    if '_otp_store' not in globals():
        _otp_store = {}
        
    otp_data = _otp_store.get(email)
    
    if not otp_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP code")
        
    if datetime.now() > otp_data["expires_at"]:
        del _otp_store[email]
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OTP has expired. Please request a new one.")
        
    if otp_data["code"] == provided_otp:
        # Clear the OTP once used
        del _otp_store[email]
        token_id = uuid.uuid4().hex[:8]
        return {
            "access_token": f"demo-token-admin-{token_id}",
            "token_type": "bearer",
            "role": "Admin",
            "user": {
                "id": token_id,
                "username": "admin",
                "email": email,
                "full_name": "Yaswanth Admin",
                "role": "Admin",
                "is_active": True,
            },
        }
    
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP code")

from fastapi import Body
@router.post("/auth/resend-otp", summary="Resend OTP email", tags=["Auth"])
async def resend_otp(payload: dict = Body(...)):
    email = payload.get("email", "").strip().lower()
    if email not in ["yaswanthavula879@gmail.com", "abdulyunus295@gmail.com"]:
        raise HTTPException(status_code=400, detail="Invalid email")
        
    import random
    from datetime import datetime, timedelta
    import smtplib
    from email.mime.text import MIMEText
    
    otp = str(random.randint(100000, 999999))
    
    global _otp_store
    if '_otp_store' not in globals():
        _otp_store = {}
    _otp_store[email] = {
        "code": otp,
        "expires_at": datetime.now() + timedelta(minutes=1)
    }
    
    try:
        import fastapi
        sender_email = "abdulyunus295@gmail.com" 
        sender_password = "xiln ujts eqra krol" 
        
        html_content = _get_otp_html(otp)
        msg = MIMEText(html_content, "html")
        msg["Subject"] = "New QSCAS Login Verification Code"
        msg["From"] = sender_email
        msg["To"] = email

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"⚠️ SMTP failed on resend: {e}")
        
    return {"message": "New OTP sent successfully"}

