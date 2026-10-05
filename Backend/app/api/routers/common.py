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
    """Execute the 15-stage ASPM scanner engine (zero external binaries).

    Track A (runtime/external): Stages 1-12
    Track B (build/internal):   Stages 13-15 (SAST, SCA, Host Scanner)
    Track C (unification):      CBOM Unification
    """
    from app.scanner.pipeline import DualTrackPipelineManager, ScanContext
    from app.scanner.engines.adaptive import AdaptiveRateController
    # Track A engines
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
    # Track B engines
    from app.scanner.engines.sast_crypto import SASTCryptoEngine
    from app.scanner.engines.sca_engine import SCAEngine
    from app.scanner.engines.host_scanner import HostScannerEngine
    # Track C engine
    from app.scanner.engines.cbom_unification import CBOMUnificationEngine

    db = get_database()
    collection = db[SCANS_COLLECTION]

    await collection.update_one(
        {"scan_id": scan_id},
        {"$set": {
            "status": ScanStatus.RUNNING.value,
            "started_at": datetime.utcnow(),
            "current_stage": "Initialising ASPM engine (15-stage dual-track)",
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

    # Resolve source_code_paths from request or env
    source_paths = getattr(request, "source_code_paths", None) or []
    if not source_paths:
        env_path = getattr(settings, "SCANNER_SOURCE_CODE_PATH", None) or ""
        if env_path:
            source_paths = [env_path]
            
    repo_urls = getattr(request, "repository_urls", None) or []
    src_scope = getattr(request, "source_scope", None) or {}
    container_imgs = getattr(request, "container_images", None) or []
    fs_paths = getattr(request, "filesystem_paths", None) or []
    insp_targets = getattr(request, "inspection_targets", None) or []

    ctx = ScanContext(
        scan_id=scan_id,
        domain=request.domain.strip().lower(),
        options={
            "scan_depth": scan_depth,
            "max_subdomains": request.max_subdomains,
            "port_profile": settings.SCANNER_PORT_PROFILE,
            "ai_adaptive": settings.SCANNER_AI_ADAPTIVE,
            # Track B options
            "source_code_paths": source_paths,
            "repository_urls": repo_urls,
            "source_scope": src_scope,
            "host_scan_paths": fs_paths or source_paths,
            "container_images": container_imgs,
            "filesystem_paths": fs_paths or source_paths,
            "inspection_targets": insp_targets,
        },
        throttle=throttle,
        broadcast=_broadcast,
        db=db,
    )

    # ── Track A: Runtime / External (existing 12 stages) ──
    track_a_stages = [
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

    # ── Track B: Build / Internal (3 new stages) ──
    track_b_stages = [
        SASTCryptoEngine(),
        SCAEngine(),
        HostScannerEngine(),
    ]

    # ── Track C: Unification (CBOM brain) ──
    track_c_stages = [
        CBOMUnificationEngine(),
    ]

    pipeline = DualTrackPipelineManager(
        track_a_stages=track_a_stages,
        track_b_stages=track_b_stages,
        track_c_stages=track_c_stages,
    )

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

        # ── Core scan data (ensure correct nesting for CBOM compliance view) ──
        if ctx.tls_profiles:
            update["tls_profiles"] = [t if isinstance(t, dict) else t for t in ctx.tls_profiles]
        if ctx.cbom:
            update["cbom"] = ctx.cbom if isinstance(ctx.cbom, dict) else ctx.cbom
            update["cbom_report"] = update["cbom"]  # Dashboard endpoints expect 'cbom_report'
        if ctx.asset_intelligence:
            update["asset_intelligence"] = ctx.asset_intelligence
        if ctx.crypto_findings:
            update["crypto_findings"] = [f if isinstance(f, dict) else f for f in ctx.crypto_findings]
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
        if ctx.quantum_score:
            update["quantum_score"] = ctx.quantum_score if isinstance(ctx.quantum_score, dict) else ctx.quantum_score

        # ── Track B: SAST / SCA / Host / Container findings ──
        if ctx.sast_findings:
            update["sast_findings"] = ctx.sast_findings
        if ctx.sca_findings:
            update["sca_findings"] = ctx.sca_findings
        if ctx.host_config_findings:
            update["host_config_findings"] = ctx.host_config_findings
        if ctx.internal_certificates:
            update["internal_certificates"] = ctx.internal_certificates
        if getattr(ctx, "crypto_observations", None):
            update["crypto_observations"] = ctx.crypto_observations
        if getattr(ctx, "container_findings", None):
            update["container_findings"] = ctx.container_findings
        if getattr(ctx, "package_findings", None):
            update["package_findings"] = ctx.package_findings

        # ── Track C: Unified CBOM Report (CERT-IN / PNB Annexure-A) ──
        if ctx.unified_cbom_report:
            update["unified_cbom_report"] = ctx.unified_cbom_report

        # Convert crypto_findings dicts → CryptoComponent objects for the engine
        _RISK_TO_QSTATUS = {
            "critical": QuantumStatus.VULNERABLE,
            "high": QuantumStatus.VULNERABLE,
            "medium": QuantumStatus.PARTIALLY_SAFE,
            "low": QuantumStatus.QUANTUM_SAFE,
            "none": QuantumStatus.QUANTUM_SAFE,
            "info": QuantumStatus.QUANTUM_SAFE,
        }

        def _get_category(comp_type: str) -> AlgorithmCategory:
            if comp_type == "cipher_kex" or comp_type == "hndl_risk" or comp_type == "forward_secrecy":
                return AlgorithmCategory.KEY_EXCHANGE
            elif comp_type == "cipher_enc" or comp_type == "crypto_score":
                return AlgorithmCategory.CIPHER
            elif comp_type == "cipher_mac":
                return AlgorithmCategory.HASH
            elif comp_type.startswith("certificate_key") or comp_type.startswith("certificate_validity") or comp_type.startswith("certificate_trust"):
                return AlgorithmCategory.SIGNATURE
            elif comp_type.startswith("cert_signature"):
                return AlgorithmCategory.HASH
            elif comp_type == "protocol":
                return AlgorithmCategory.PROTOCOL
            return AlgorithmCategory.CIPHER

        all_components: list[CryptoComponent] = []
        for fd in (ctx.crypto_findings or []):
            f = fd if isinstance(fd, dict) else {}
            comp_type = f.get("component", "")
            algo = f.get("algorithm", "unknown")
            qr = f.get("quantum_risk", "medium")

            # Skip composite score rows — not real components
            if comp_type == "crypto_score":
                continue

            cat = _get_category(comp_type)
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

        # ── Track C: Unified CBOM Report card ──
        unified_cbom = ctx.unified_cbom_report or {}
        if unified_cbom:
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "unified_cbom",
                "payload": {
                    "domain": ctx.domain,
                    "compliance_standard": (unified_cbom.get("CBOM_Metadata") or {}).get("compliance_standard", ""),
                    "total_algorithms": len(unified_cbom.get("Algorithms") or []),
                    "total_certificates": len(unified_cbom.get("Certificates") or []),
                    "total_keys": len(unified_cbom.get("Keys") or []),
                    "total_protocols": len(unified_cbom.get("Protocols") or []),
                },
            }, scan_id)

        # ── Track B summary card ──
        if ctx.sast_findings or ctx.sca_findings or ctx.internal_certificates:
            await ws_manager.broadcast({
                "type": "result",
                "result_type": "track_b_summary",
                "payload": {
                    "sast_findings_count": len(ctx.sast_findings or []),
                    "sca_findings_count": len(ctx.sca_findings or []),
                    "host_config_findings_count": len(ctx.host_config_findings or []),
                    "internal_certificates_count": len(ctx.internal_certificates or []),
                    "hardcoded_secrets": sum(
                        1 for f in (ctx.sast_findings or [])
                        if isinstance(f, dict) and f.get("finding_type") == "hardcoded_secret"
                    ),
                    "vulnerable_deps": sum(
                        1 for f in (ctx.sca_findings or [])
                        if isinstance(f, dict) and f.get("is_vulnerable")
                    ),
                },
            }, scan_id)

        await ws_manager.broadcast({
            "type": "status",
            "status": "completed",
            "message": "15-stage ASPM scan completed.",
        }, scan_id)

        logger.info("[%s] 15-stage ASPM scan completed.", scan_id)

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

        # Removed legacy run_nuclei_scan bypass
        vuln_findings = []

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "headers_results": [h.model_dump(mode="json") for h in headers_results],
                "assets": [a.model_dump(mode="json") for a in assets],
                "vuln_findings": vuln_findings,
                "current_stage": "HTTP Headers",
                "progress": 95,
            }},
        )

        # ── Stage 8: CVE / Known-Attack Mapping ──────────────────
        logger.info("[%s] Stage 8/8: CVE / Known-Attack Mapping (Legacy step removed)", scan_id)
        cve_findings = []

        await collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "cve_findings": cve_findings,
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


def _notification_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: doc[k] for k in doc if k != "_id"}
    return out


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


class OTPPayload(BaseModel):
    email: str
    otp: str


from fastapi import Body
