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



@router.get("/cbom/summary", tags=["CBOM"])
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


@router.get("/cbom/per-app", tags=["CBOM"])
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
        try:
            cbom_report = doc.get("cbom_report") or {}
            components = cbom_report.get("components")
            
            # Fallback to raw cbom array if report was not generated
            if not components:
                components = doc.get("cbom", [])
            for c in components:
                try:
                    c_dict = dict(c)
                except (TypeError, ValueError):
                    continue
                domain_val = doc.get("domain", "")
                
                # Deduplicate
                sig = (domain_val, c_dict.get("name"), c_dict.get("category"), c_dict.get("key_size"))
                if sig in seen:
                    continue
                seen.add(sig)
                
                enriched = enrich_cbom_component_dict(c_dict)
                enriched["domain"] = domain_val
                all_components.append(enriched)
        except Exception as exc:
            logger.warning("Skipping malformed CBOM doc %s: %s", doc.get("scan_id"), exc)
        
    return all_components


@router.get("/cbom/compliance-view", tags=["CBOM"])
async def get_cbom_compliance_view(domain: str = None):
    """
    Returns CBOM data structured into 4 strict asset categories:
    Certificates, Protocols, Keys, Algorithms — matching CERT-IN Annexure-A format.
    """
    db = get_database()
    query: Dict[str, Any] = {"status": "completed"}
    if domain:
        query["domain"] = domain

    doc = await db[SCANS_COLLECTION].find_one(query, sort=[("completed_at", -1)])
    if not doc:
        return {"certificates": [], "protocols": [], "keys": [], "algorithms": []}

    scan_domain = doc.get("domain", "")

    # ── Source 1: TLS results (rich cert + negotiated TLS data) ──
    tls_results = doc.get("tls_results") or []

    # ── Source 2: CBOM report components (algorithm/cipher detail) ──
    cbom_report = doc.get("cbom") or doc.get("cbom_report") or {}
    cbom_components = cbom_report.get("components") or []

    # ── Source 3: Custom engine TLS profiles (cipher detail with new fields) ──
    custom_assets = doc.get("asset_intelligence") or []
    tls_profiles_raw: list = []
    for asset in custom_assets:
        if isinstance(asset, dict):
            tls_profiles_raw.extend(asset.get("tls_profiles") or [])

    certificates: list = []
    protocols: list = []
    keys: list = []
    algorithms: list = []

    seen_certs: set = set()
    seen_protocols: set = set()
    seen_keys: set = set()
    seen_algos: set = set()

    # ── Extract from TLS results (V1) and TLS Profiles (V2) ──
    all_tls = doc.get("tls_results", []) + doc.get("tls_profiles", [])
    for t in all_tls:
        host = t.get("host") or scan_domain
        
        # Normalize V1 ('certificate') vs V2 ('leaf_cert')
        cert = t.get("certificate") or t.get("leaf_cert") or {}

        # Certificate
        subject = cert.get("subject") or host
        sig = f"{host}|{subject}"
        if cert and sig not in seen_certs:
            seen_certs.add(sig)
            
            # Normalize field names
            issuer = cert.get("issuer") or "Unknown"
            not_before = cert.get("not_before") or cert.get("valid_from") or "—"
            not_after = cert.get("not_after") or cert.get("valid_to") or "—"
            sig_alg = cert.get("signature_algorithm") or cert.get("sig_algorithm") or "—"
            
            pk_alg = cert.get("public_key_algorithm") or cert.get("key_type") or ""
            pk_size = cert.get("public_key_size") or cert.get("key_size") or ""
            pk_ref = pk_alg
            if pk_size:
                pk_ref = f"{pk_alg} ({pk_size})"
                
            certificates.append({
                "name": subject,
                "asset_type": "certificate",
                "subject_name": subject,
                "issuer_name": issuer,
                "not_valid_before": not_before,
                "not_valid_after": not_after,
                "sig_algorithm_ref": sig_alg,
                "subject_public_key_ref": pk_ref,
                "certificate_format": "X.509",
                "certificate_extension": ".crt",
            })

        # Protocol
        tls_ver = t.get("tls_version") or ""
        if tls_ver:
            proto_key = f"{host}|{tls_ver}"
            if proto_key not in seen_protocols:
                seen_protocols.add(proto_key)
                protocols.append({
                    "name": tls_ver,
                    "asset_type": "protocol",
                    "version": tls_ver,
                    "cipher_suites": t.get("cipher_suite") or "—",
                    "oid": "—",
                })

        # Key (derived from certificate public key)
        if cert:
            pk_alg = cert.get("public_key_algorithm") or "Unknown"
            pk_size = cert.get("public_key_size")
            key_sig = f"{host}|{pk_alg}|{pk_size}"
            if key_sig not in seen_keys:
                seen_keys.add(key_sig)
                days = cert.get("days_until_expiry")
                state = "Expired" if (days is not None and days < 0) else "Active"
                keys.append({
                    "name": f"{pk_alg}-{pk_size}" if pk_size else pk_alg,
                    "asset_type": "key",
                    "id": "—",
                    "state": state,
                    "size": f"{pk_size}-bit" if pk_size else "—",
                    "creation_date": cert.get("not_before") or "—",
                    "activation_date": cert.get("not_before") or "—",
                })

    # ── Enrich from CBOM report components (custom engine data) ──
    for comp in cbom_components:
        asset_type = comp.get("asset_type") or ""
        host_val = comp.get("host") or scan_domain
        elements = comp.get("elements") or {}

        if asset_type == "certificate":
            subject = elements.get("subject") or comp.get("name") or host_val
            sig = f"{host_val}|{subject}"
            if sig not in seen_certs:
                seen_certs.add(sig)
                certificates.append({
                    "name": subject,
                    "asset_type": "certificate",
                    "subject_name": elements.get("subject") or subject,
                    "issuer_name": elements.get("issuer") or "Unknown",
                    "not_valid_before": elements.get("not_valid_before") or "—",
                    "not_valid_after": elements.get("not_valid_after") or "—",
                    "sig_algorithm_ref": elements.get("signature_algorithm") or "—",
                    "subject_public_key_ref": elements.get("subject_public_key_ref") or elements.get("public_key") or "—",
                    "certificate_format": elements.get("certificate_format") or "X.509",
                    "certificate_extension": elements.get("certificate_extension") or ".crt",
                })
            # Key from certificate
            key_type = elements.get("key_type")
            key_size = elements.get("key_size")
            key_id_val = elements.get("key_id") or "—"
            key_sig = f"{host_val}|{key_type}|{key_size}"
            if key_type and key_sig not in seen_keys:
                seen_keys.add(key_sig)
                nvb = elements.get("not_valid_before") or "—"
                nva = elements.get("not_valid_after") or "—"
                state = "Expired" if comp.get("risk_level") == "critical" and "expir" in str(comp.get("name") or "").lower() else "Active"
                keys.append({
                    "name": f"{key_type}-{key_size}" if key_size else (key_type or "—"),
                    "asset_type": "key",
                    "id": key_id_val,
                    "state": state,
                    "size": f"{key_size}-bit" if key_size else "—",
                    "creation_date": nvb,
                    "activation_date": nvb,
                })

        elif asset_type == "protocol":
            proto_key = f"{host_val}|{comp.get('name')}"
            if proto_key not in seen_protocols:
                seen_protocols.add(proto_key)
                protocols.append({
                    "name": comp.get("name") or "—",
                    "asset_type": "protocol",
                    "version": comp.get("name") or "—",
                    "cipher_suites": "—",
                    "oid": "—",
                })

        elif asset_type == "algorithm":
            algo_key = f"{host_val}|{comp.get('name')}"
            if algo_key not in seen_algos:
                seen_algos.add(algo_key)
                algorithms.append({
                    "name": comp.get("name") or "—",
                    "asset_type": "algorithm",
                    "primitive": comp.get("primitive") or "—",
                    "mode": comp.get("mode") or "—",
                    "crypto_functions": comp.get("crypto_functions") or "—",
                    "classical_security_level": f"{comp.get('classical_security_level')}-bit" if comp.get("classical_security_level") else "—",
                    "oid": comp.get("oid") or "—",
                    "cipher_name": comp.get("cipher_name") or "—",
                    "risk_level": comp.get("risk_level") or "low",
                    "quantum_status": comp.get("quantum_status") or "vulnerable",
                    "recommendation": comp.get("nist_primary_recommendation") or "—",
                })

    # ── Enrich from custom-engine TLS profiles (deepest detail) ──
    for profile in tls_profiles_raw:
        if not isinstance(profile, dict):
            continue
        host_val = profile.get("host") or scan_domain

        # Protocols from supported versions
        for ver, supported in (profile.get("tls_versions_supported") or {}).items():
            if not supported:
                continue
            clean_name = ver.replace("_", ".")
            proto_key = f"{host_val}|{clean_name}"
            if proto_key not in seen_protocols:
                seen_protocols.add(proto_key)
                neg = profile.get("negotiated_cipher") or "—"
                protocols.append({
                    "name": clean_name,
                    "asset_type": "protocol",
                    "version": clean_name,
                    "cipher_suites": neg,
                    "oid": "—",
                })

        # Algorithms from accepted ciphers
        for cipher in (profile.get("accepted_ciphers") or []):
            c = cipher if isinstance(cipher, dict) else {}
            c_name = c.get("name") or c.get("kex") or "—"
            algo_key = f"{host_val}|{c_name}"
            if algo_key not in seen_algos:
                seen_algos.add(algo_key)
                algorithms.append({
                    "name": c_name,
                    "asset_type": "algorithm",
                    "primitive": c.get("primitive") or "—",
                    "mode": c.get("mode") or "—",
                    "crypto_functions": c.get("crypto_functions") or "—",
                    "classical_security_level": f"{c.get('classical_security_level')}-bit" if c.get("classical_security_level") else "—",
                    "oid": c.get("oid") or "—",
                    "cipher_name": c.get("name") or "—",
                    "risk_level": "medium",
                    "quantum_status": "vulnerable",
                    "recommendation": "Upgrade to PQC-ready algorithm",
                })

        # Certificate + Key from leaf_cert
        leaf = profile.get("leaf_cert") or {}
        if leaf:
            subject = leaf.get("subject") or host_val
            sig = f"{host_val}|{subject}"
            if sig not in seen_certs:
                seen_certs.add(sig)
                certificates.append({
                    "name": subject,
                    "asset_type": "certificate",
                    "subject_name": subject,
                    "issuer_name": leaf.get("issuer") or "Unknown",
                    "not_valid_before": leaf.get("valid_from") or "—",
                    "not_valid_after": leaf.get("valid_to") or "—",
                    "sig_algorithm_ref": leaf.get("sig_algorithm") or "—",
                    "subject_public_key_ref": leaf.get("subject_public_key_ref") or f"{leaf.get('key_type') or ''}-{leaf.get('key_size') or ''}",
                    "certificate_format": leaf.get("certificate_format") or "X.509",
                    "certificate_extension": leaf.get("certificate_extension") or ".crt",
                })
            key_type = leaf.get("key_type")
            key_size = leaf.get("key_size")
            key_sig = f"{host_val}|{key_type}|{key_size}"
            if key_type and key_sig not in seen_keys:
                seen_keys.add(key_sig)
                days = leaf.get("days_until_expiry")
                state = "Expired" if (days is not None and days < 0) else "Active"
                keys.append({
                    "name": f"{key_type}-{key_size}" if key_size else key_type,
                    "asset_type": "key",
                    "id": leaf.get("key_id") or "—",
                    "state": state,
                    "size": f"{key_size}-bit" if key_size else "—",
                    "creation_date": leaf.get("valid_from") or "—",
                    "activation_date": leaf.get("valid_from") or "—",
                })

    return {
        "domain": scan_domain,
        "certificates": certificates,
        "protocols": protocols,
        "keys": keys,
        "algorithms": algorithms,
    }


@router.get("/cbom/charts", tags=["CBOM"])
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

    WEAK_MARKERS = ("MD5", "RC4", "DES", "NULL", "EXPORT", "anon")

    for scan in scans:
        # ── Source 1: V2 engine tls_profiles (richest data) ──────────────────
        for profile in (scan.get("tls_profiles") or []):
            if not isinstance(profile, dict):
                continue

            host = profile.get("host", "")

            # Negotiated TLS version
            neg_cipher = profile.get("negotiated_cipher")
            versions_map = profile.get("tls_versions_supported") or {}

            # Determine the negotiated TLS version label from the versions map
            # Prefer highest supported: 1.3 > 1.2 > 1.1 > 1.0
            bucket = None
            for vk in ("TLSv1_3", "TLSv1_2", "TLSv1_1", "TLSv1"):
                if versions_map.get(vk):
                    bucket = _normalize_negotiated_tls_label(vk.replace("_", "."))
                    break
            if bucket:
                negotiated_tls[bucket] = negotiated_tls.get(bucket, 0) + 1

            # Cipher suites
            for cipher in (profile.get("accepted_ciphers") or []):
                if not isinstance(cipher, dict):
                    continue
                cname = cipher.get("name") or cipher.get("kex") or ""
                if not cname:
                    continue
                is_weak = any(m in cname for m in WEAK_MARKERS)
                cipher_usage[cname] = {"count": cipher_usage.get(cname, {}).get("count", 0) + 1, "weak": is_weak}

                # Key length from cipher bits
                bits = cipher.get("bits") or cipher.get("classical_security_level")
                if bits:
                    ks = str(bits)
                    key_lengths[ks] = key_lengths.get(ks, 0) + 1

            # Leaf cert → CA + key length
            leaf = profile.get("leaf_cert") or {}
            if leaf:
                raw_iss = leaf.get("issuer") or ""
                ca = normalize_ca_display_name(raw_iss)
                cas[ca] = cas.get(ca, 0) + 1

                key_size = leaf.get("key_size")
                if key_size:
                    ks = str(key_size)
                    key_lengths[ks] = key_lengths.get(ks, 0) + 1

        # ── Source 2: V1 engine tls_results ──────────────────────────────────
        for t in (scan.get("tls_results") or []):
            if not isinstance(t, dict):
                continue
            raw_iss = extract_issuer_raw_from_tls_row(t)
            ca = normalize_ca_display_name(raw_iss)
            cas[ca] = cas.get(ca, 0) + 1

            if not t.get("error"):
                bucket = _normalize_negotiated_tls_label(t.get("tls_version"))
                negotiated_tls[bucket] = negotiated_tls.get(bucket, 0) + 1

            cs = t.get("cipher_suite")
            if cs:
                is_weak = any(m in str(cs) for m in WEAK_MARKERS)
                entry = cipher_usage.get(cs, {"count": 0, "weak": is_weak})
                entry["count"] += 1
                cipher_usage[cs] = entry

            cb = t.get("cipher_bits") or t.get("key_length")
            if cb:
                ks = str(cb)
                key_lengths[ks] = key_lengths.get(ks, 0) + 1

        # ── Source 3: cbom_report components ─────────────────────────────────
        cr = scan.get("cbom_report") or {}
        for c in (cr.get("components") or []):
            if not isinstance(c, dict):
                continue
            category = c.get("category", "")
            cname = c.get("name", "Unknown")
            if category == "protocol":
                tls_versions[cname] = tls_versions.get(cname, 0) + 1
            elif category == "cipher":
                entry = cipher_usage.get(cname, {"count": 0, "weak": False})
                entry["count"] += 1
                cipher_usage[cname] = entry
                ks = str(c.get("key_size") or "2048")
                key_lengths[ks] = key_lengths.get(ks, 0) + 1

        # ── Source 4: crypto_findings (fallback) ──────────────────────────────
        for f in (scan.get("crypto_findings") or []):
            if not isinstance(f, dict):
                continue
            comp = f.get("component", "")
            algo = f.get("algorithm", "")
            if comp == "protocol" and algo:
                bucket = _normalize_negotiated_tls_label(algo)
                negotiated_tls[bucket] = negotiated_tls.get(bucket, 0) + 1
            elif comp in ("cipher_enc", "cipher_kex") and algo:
                is_weak = any(m in algo for m in WEAK_MARKERS)
                entry = cipher_usage.get(algo, {"count": 0, "weak": is_weak})
                entry["count"] += 1
                cipher_usage[algo] = entry

    # ── Build sorted output ───────────────────────────────────────────────────
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

    # Normalize key_lengths — sort by numeric bit size
    kl_rows = sorted(
        [{"name": k, "count": v} for k, v in key_lengths.items()],
        key=lambda r: int(r["name"]) if str(r["name"]).isdigit() else 0,
    )

    # Normalize cipher_usage — dict values may be int (old) or dict (new)
    cu_rows = []
    for k, v in cipher_usage.items():
        if isinstance(v, dict):
            cu_rows.append({"name": k, "count": v.get("count", 1), "weak": v.get("weak", False)})
        else:
            is_weak = any(m in str(k) for m in WEAK_MARKERS)
            cu_rows.append({"name": k, "count": int(v), "weak": is_weak})
    cu_rows.sort(key=lambda r: -r["count"])

    return {
        "key_length_distribution": kl_rows,
        "top_certificate_authorities": ca_chart,
        "encryption_protocols": enc_rows,
        "cipher_usage": cu_rows,
    }


@router.get("/cbom/{domain}", tags=["CBOM"])
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


@router.get("/quantum-score/{domain}", tags=["CBOM"])
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


@router.get("/security-roadmap/latest", tags=["CBOM"])
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


@router.get("/security-roadmap/scan/{scan_id}", tags=["CBOM"])
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


@router.get("/security-roadmap/{domain}", tags=["CBOM"])
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


@router.get("/crypto/security", tags=["CBOM"])
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
        try:
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
                try:
                    host = (t.get("host") or scan.get("domain", "")).lower()
                    port = t.get("port", 443)
                    key = f"{host}:{port}"
                    
                    asset_slug = classify_asset_service(services=host_services.get(host))
                    raw_iss = extract_issuer_raw_from_tls_row(t)
                    cert = t.get("certificate") or t.get("leaf_cert") or {}
                    
                    # Extract fields
                    tls_version = t.get("tls_version") or "TLS 1.3" if t.get("tls_versions_supported", {}).get("TLSv1_3") else ""
                    cipher_suite = t.get("cipher_suite") or t.get("negotiated_cipher") or ""
                    key_length_val = str(t.get('cipher_bits') or cert.get('key_size') or "")
                    
                    # Estimate key exchange if not present explicitly
                    key_exchange = t.get("key_exchange", "")
                    if key_exchange == "UNKNOWN" or not key_exchange:
                        if cipher_suite.startswith("TLS_AES") or cipher_suite.startswith("TLS_CHACHA20"):
                            key_exchange = "TLSv1.3 Default"
                        else:
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
                except Exception as tls_exc:
                    logger.warning("Skipping malformed TLS row in scan %s: %s", scan.get("scan_id"), tls_exc)
        except Exception as scan_exc:
            logger.warning("Skipping malformed scan doc %s: %s", scan.get("scan_id"), scan_exc)

    return list(results_dict.values())


@router.get("/crypto/scan-findings", tags=["CBOM"])
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


@router.get("/pqc/posture", tags=["CBOM"])
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


@router.get("/pqc/vulnerable-algorithms", tags=["CBOM"])
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


@router.get("/pqc/risk-categories", tags=["CBOM"])
async def get_pqc_risk_categories():
    return []


@router.get("/pqc/compliance", tags=["CBOM"])
async def get_pqc_compliance():
    return []


@router.get("/cyber-rating", tags=["CBOM"])
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


@router.get("/cyber-rating/history", tags=["CBOM"])
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


@router.post("/quantum-score/simulate", tags=["CBOM"])
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


@router.get("/cyber-rating/risk-factors", tags=["CBOM"])
async def get_risk_factors():
    return []


@router.get("/threat-model/summary", tags=["CBOM"])
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


@router.get("/threat-model/nist-catalog", tags=["CBOM"])
async def get_nist_catalog():
    """Reference links for UI and export — not legal/compliance advice."""
    return {"references": NIST_PQC_REFERENCES}
