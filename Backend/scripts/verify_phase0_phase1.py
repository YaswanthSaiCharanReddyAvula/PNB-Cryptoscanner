#!/usr/bin/env python3
"""
Verify Phase 0–7 conditions (baseline through operational ops snapshot).

Usage (from repo root or Backend/):
  cd Backend && python scripts/verify_phase0_phase1.py

Exit code 0 = all checks passed; non-zero = failure.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

# Backend root (parent of scripts/)
BACKEND = Path(__file__).resolve().parent.parent
ROOT_FILES = {
    "main": BACKEND / "app" / "main.py",
    "routes": BACKEND / "app" / "api" / "routes.py",
    "ws": BACKEND / "app" / "api" / "v1" / "ws.py",
    "ws_manager": BACKEND / "app" / "core" / "ws_manager.py",
    "config": BACKEND / "app" / "config.py",
    "phase0_doc": BACKEND / "docs" / "PHASE0_BASELINE.md",
    "phase2_doc": BACKEND / "docs" / "PHASE2_BASELINE.md",
    "phase3_doc": BACKEND / "docs" / "PHASE3_BASELINE.md",
    "phase4_doc": BACKEND / "docs" / "PHASE4_BASELINE.md",
    "phase5_doc": BACKEND / "docs" / "PHASE5_BASELINE.md",
    "phase6_doc": BACKEND / "docs" / "PHASE6_BASELINE.md",
    "phase7_doc": BACKEND / "docs" / "PHASE7_BASELINE.md",
    "policy_alignment": BACKEND / "app" / "utils" / "policy_alignment.py",
    "threat_nist": BACKEND / "app" / "modules" / "threat_nist_mapping.py",
}

FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"OK:   {msg}")


def read(name: str) -> str:
    p = ROOT_FILES[name]
    if not p.is_file():
        fail(f"Missing file: {p}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def phase0_routing_and_health() -> None:
    main = read("main")
    if not main:
        return
    if 'prefix="/api/v1"' not in main and "prefix='/api/v1'" not in main:
        fail("main.py: scanner router not mounted with prefix /api/v1")
    else:
        ok("main.py: REST mounted at /api/v1")

    if "ws_router" not in main:
        fail("main.py: ws_router not included")
    else:
        ok("main.py: WebSocket router included at app root (no /api/v1 on ws router)")

    if re.search(r'@app\.get\(\s*["\']/health', main):
        ok("main.py: GET /health present")
    else:
        fail("main.py: GET /health not found")

    ws = read("ws")
    if not ws:
        return
    if '@router.websocket("/ws/scan/{scan_id}")' in ws or "@router.websocket('/ws/scan/{scan_id}')" in ws:
        ok("ws.py: WebSocket path /ws/scan/{scan_id}")
    else:
        fail("ws.py: expected @router.websocket(\"/ws/scan/{scan_id}\")")


def phase0_collections() -> None:
    routes = read("routes")
    if not routes:
        return
    expected = {
        "SCANS_COLLECTION": "scans",
        "ASSET_METADATA_COLLECTION": "asset_metadata",
        "ORG_POLICY_COLLECTION": "org_policy",
        "INTEGRATION_SETTINGS_COLLECTION": "integration_settings",
        "EXPORT_AUDIT_COLLECTION": "export_audit",
        "MIGRATION_TASKS_COLLECTION": "migration_tasks",
        "WAIVERS_COLLECTION": "waivers",
        "REGISTERED_ASSETS_COLLECTION": "registered_assets",
        "SBOM_ARTIFACTS_COLLECTION": "sbom_artifacts",
    }
    for const, val in expected.items():
        if f'{const} = "{val}"' in routes:
            ok(f"routes.py: {const} = {val!r}")
        else:
            fail(f"routes.py: expected {const} = \"{val}\"")


def phase0_sample_endpoints() -> None:
    routes = read("routes")
    if not routes:
        return
    needles = [
        ('POST', '"/scan"'),
        ('POST', '"/scan/batch"'),
        ('GET', '"/results/{domain}"'),
        ('GET', '"/scans/history"'),
        ('GET', '"/cbom/summary"'),
        ('POST', '"/auth/login"'),
        ('GET', '"/dashboard/summary"'),
        ('GET', '"/scans/recent"'),
        ('POST', '"/quantum-score/simulate"'),
        ('GET', '"/threat-model/summary"'),
        ('POST', '"/inventory/sources/import"'),
    ]
    for _method, path in needles:
        if path in routes:
            ok(f"routes.py: endpoint path fragment {path}")
        else:
            fail(f"routes.py: missing path {path}")


def phase0_config_settings() -> None:
    cfg = read("config")
    if not cfg:
        return
    fields = [
        "APP_NAME",
        "APP_VERSION",
        "MONGO_URI",
        "MONGO_DB_NAME",
        "SECRET_KEY",
        "MAX_CONCURRENT_SCANS",
        "MAX_BATCH_DOMAINS",
        "MAX_SUBDOMAINS",
    ]
    for f in fields:
        if re.search(rf"^\s*{f}\s*:", cfg, re.MULTILINE):
            ok(f"config.py: Settings field {f}")
        else:
            fail(f"config.py: missing Settings field {f}")


def phase0_doc_exists() -> None:
    p = ROOT_FILES["phase0_doc"]
    if p.is_file():
        ok(f"docs: {p.name} present")
    else:
        fail(f"docs: PHASE0_BASELINE.md missing at {p}")


def phase2_portfolio() -> None:
    routes = read("routes")
    if not routes:
        return
    if '"/scans/recent"' in routes and "async def scans_recent" in routes:
        ok("routes.py: GET /scans/recent + scans_recent handler")
    else:
        fail("routes.py: missing GET /scans/recent handler")

    if "_scan_sem = asyncio.Semaphore" in routes and "max(1, settings.MAX_CONCURRENT_SCANS)" in routes:
        ok("routes.py: global _scan_sem uses MAX_CONCURRENT_SCANS")
    else:
        fail("routes.py: expected _scan_sem from MAX_CONCURRENT_SCANS")

    if "async def _run_scan_pipeline_gated" in routes:
        ok("routes.py: _run_scan_pipeline_gated defined")
    else:
        fail("routes.py: _run_scan_pipeline_gated missing")

    n_gated = routes.count("add_task(_run_scan_pipeline_gated")
    if n_gated >= 2:
        ok(f"routes.py: start_scan + batch use gated pipeline ({n_gated} add_task sites)")
    else:
        fail("routes.py: expected both /scan and /scan/batch to call _run_scan_pipeline_gated")

    if "batch_id" in routes and '"/scan/batch"' in routes:
        ok("routes.py: batch scan sets batch_id")
    else:
        fail("routes.py: batch_id wiring unclear")

    cfg = read("config")
    if cfg and "MAX_BATCH_DOMAINS" in cfg and "MAX_CONCURRENT_SCANS" in cfg:
        ok("config.py: Phase 2 portfolio settings present")
    else:
        fail("config.py: MAX_BATCH_DOMAINS / MAX_CONCURRENT_SCANS")

    p2 = ROOT_FILES["phase2_doc"]
    if p2.is_file():
        ok(f"docs: {p2.name} present")
    else:
        fail(f"docs: PHASE2_BASELINE.md missing at {p2}")


def phase3_analysis_depth() -> None:
    routes = read("routes")
    tnm = read("threat_nist")
    if not routes or not tnm:
        return

    if "def enrich_cbom_component_dict" in tnm:
        ok("threat_nist_mapping.py: enrich_cbom_component_dict")
    else:
        fail("threat_nist_mapping.py: missing enrich_cbom_component_dict")

    if "enrich_cbom_component_dict" in routes and "get_cbom_per_app" in routes:
        ok("routes.py: CBOM per-app uses enrichment")
    else:
        fail("routes.py: expected enrich_cbom_component_dict on per-app CBOM path")

    if '"/quantum-score/simulate"' in routes and "simulate_quantum_score_endpoint" in routes:
        ok("routes.py: POST /quantum-score/simulate")
    else:
        fail("routes.py: missing quantum score simulate endpoint")

    if '"/threat-model/summary"' in routes and "get_threat_model_summary" in routes:
        ok("routes.py: GET /threat-model/summary")
    else:
        fail("routes.py: missing threat-model summary")

    if '"/threat-model/nist-catalog"' in routes:
        ok("routes.py: GET /threat-model/nist-catalog")
    else:
        fail("routes.py: missing threat-model nist-catalog")

    p3 = ROOT_FILES["phase3_doc"]
    if p3.is_file():
        ok(f"docs: {p3.name} present")
    else:
        fail(f"docs: PHASE3_BASELINE.md missing at {p3}")


def phase4_policy_integrations() -> None:
    routes = read("routes")
    pa = read("policy_alignment")
    if not routes or not pa:
        return
    if '"/dashboard/policy-alignment"' in routes and "get_policy_alignment" in routes:
        ok("routes.py: GET /dashboard/policy-alignment")
    else:
        fail("routes.py: missing GET /dashboard/policy-alignment")

    if '"/admin/exports/log"' in routes and "post_export_audit_log" in routes:
        ok("routes.py: POST /admin/exports/log")
    else:
        fail("routes.py: missing POST /admin/exports/log")

    if "post_slack_incoming_webhook" in routes and "slack_webhook_url" in routes:
        ok("routes.py: scan-complete hooks reference Slack helper + slack URL")
    else:
        fail("routes.py: expected Slack webhook wiring in notify hooks")

    if "def summarize_tls_vs_policy" in pa:
        ok("policy_alignment.py: summarize_tls_vs_policy")
    else:
        fail("policy_alignment.py: missing summarize_tls_vs_policy")

    p4 = ROOT_FILES["phase4_doc"]
    if p4.is_file():
        ok(f"docs: {p4.name} present")
    else:
        fail(f"docs: PHASE4_BASELINE.md missing at {p4}")

    wn = BACKEND / "app" / "modules" / "webhook_notify.py"
    wnt = wn.read_text(encoding="utf-8", errors="replace") if wn.is_file() else ""
    if "post_slack_incoming_webhook" in wnt:
        ok("webhook_notify.py: post_slack_incoming_webhook")
    else:
        fail("webhook_notify.py: post_slack_incoming_webhook missing")


def phase5_migration_execution() -> None:
    routes = read("routes")
    if not routes:
        return
    if '"/dashboard/migration-snapshot"' in routes and "get_migration_snapshot" in routes:
        ok("routes.py: GET /dashboard/migration-snapshot")
    else:
        fail("routes.py: missing GET /dashboard/migration-snapshot")

    if '"/migration/tasks/seed-from-backlog"' in routes and "seed_tasks_from_backlog" in routes:
        ok("routes.py: POST /migration/tasks/seed-from-backlog")
    else:
        fail("routes.py: missing seed-from-backlog endpoint")

    if '"created_by": _user.email' in routes and "create_waiver" in routes:
        ok("routes.py: create_waiver stores created_by")
    else:
        fail("routes.py: create_waiver should set created_by from current user")

    if "list_migration_tasks" in routes and "status_filter" in routes:
        ok("routes.py: list_migration_tasks supports filters")
    else:
        fail("routes.py: list_migration_tasks missing status_filter wiring")

    p5 = ROOT_FILES["phase5_doc"]
    if p5.is_file():
        ok(f"docs: {p5.name} present")
    else:
        fail(f"docs: PHASE5_BASELINE.md missing at {p5}")


def phase6_executive_brief() -> None:
    routes = read("routes")
    if not routes:
        return
    if '"/dashboard/executive-brief"' in routes and "get_executive_brief" in routes:
        ok("routes.py: GET /dashboard/executive-brief")
    else:
        fail("routes.py: missing GET /dashboard/executive-brief")

    if "def _compute_dashboard_kpis_from_completed_scans" in routes:
        ok("routes.py: shared _compute_dashboard_kpis_from_completed_scans")
    else:
        fail("routes.py: expected KPI helper for summary + executive brief")

    p6 = ROOT_FILES["phase6_doc"]
    if p6.is_file():
        ok(f"docs: {p6.name} present")
    else:
        fail(f"docs: PHASE6_BASELINE.md missing at {p6}")


def phase7_ops_snapshot() -> None:
    routes = read("routes")
    if not routes:
        return
    if '"/dashboard/ops-snapshot"' in routes and "get_ops_snapshot" in routes:
        ok("routes.py: GET /dashboard/ops-snapshot")
    else:
        fail("routes.py: missing GET /dashboard/ops-snapshot")

    idx = routes.find("async def get_ops_snapshot")
    head = routes[idx : idx + 320] if idx >= 0 else ""
    if idx >= 0 and "Depends(require_admin)" in head:
        ok("routes.py: get_ops_snapshot uses require_admin")
    else:
        fail("routes.py: get_ops_snapshot should depend on require_admin")

    if 'await db.command("ping")' in routes:
        ok("routes.py: ops snapshot pings MongoDB")
    else:
        fail("routes.py: ops snapshot should call db.command('ping')")

    p7 = ROOT_FILES["phase7_doc"]
    if p7.is_file():
        ok(f"docs: {p7.name} present")
    else:
        fail(f"docs: PHASE7_BASELINE.md missing at {p7}")


def phase1_pipeline_docstring_and_logs() -> None:
    routes = read("routes")
    if not routes:
        return
    m = re.search(
        r'async def _run_scan_pipeline\([^)]*\)\s*->\s*None:\s*\n\s+"""(.*?)"""',
        routes,
        re.DOTALL,
    )
    if not m:
        fail("Could not parse _run_scan_pipeline docstring")
        doc = ""
    else:
        doc = m.group(1)
        if "PostgreSQL" in doc:
            fail("_run_scan_pipeline docstring still mentions PostgreSQL")
        else:
            ok("_run_scan_pipeline docstring: no PostgreSQL")
        if "8 stages" not in doc and "8 stage" not in doc:
            fail("_run_scan_pipeline docstring should mention 8 stages")
        else:
            ok("_run_scan_pipeline docstring mentions 8 stages")

    if re.search(r'Stage \d+/9', routes):
        fail("routes.py: found obsolete Stage N/9 log pattern")
    else:
        ok("routes.py: no Stage N/9 log lines")

    for n in range(1, 8):
        if f"Stage {n}/8" in routes:
            ok(f"routes.py: Stage {n}/8 log present")
        else:
            fail(f"routes.py: missing Stage {n}/8 log line")

    if "Stage 8/8" in routes:
        ok("routes.py: Stage 8/8 log present")
    else:
        fail("routes.py: missing Stage 8/8 log line")


def phase1_failure_broadcast() -> None:
    routes = read("routes")
    if not routes:
        return
    idx = routes.find("except Exception as exc:")
    if idx < 0:
        fail("routes.py: exception handler not found")
        return
    tail = routes[idx : idx + 2500]
    if '"status": "failed"' in tail and "ws_manager.broadcast" in tail:
        ok("routes.py: except block broadcasts ws status failed")
    else:
        fail("routes.py: except block missing ws_manager.broadcast with status failed")


def phase1_ws_manager_enrich() -> None:
    wm = read("ws_manager")
    if not wm:
        return
    if "def enrich_ws_payload" in wm:
        ok("ws_manager.py: enrich_ws_payload defined")
    else:
        fail("ws_manager.py: enrich_ws_payload missing")

    if "enrich_ws_payload(message" in wm or "enrich_ws_payload(message, scan_id)" in wm:
        ok("ws_manager.py: broadcast enriches dict payloads")
    elif "isinstance(message, dict)" in wm and "enrich_ws_payload" in wm:
        ok("ws_manager.py: broadcast enriches dict payloads")
    else:
        fail("ws_manager.py: broadcast should call enrich_ws_payload for dicts")


def phase1_ws_poll_frames() -> None:
    ws = read("ws")
    if not ws:
        return
    if "enrich_ws_payload" not in ws:
        fail("ws.py: should import/use enrich_ws_payload")
    else:
        ok("ws.py: uses enrich_ws_payload")

    # Each branch should set type status (three enrich_ws_payload call sites with type)
    count = ws.count('"type": "status"')
    if count >= 3:
        ok(f'ws.py: at least 3 "type": "status" frames (found {count})')
    else:
        fail(f'ws.py: expected >=3 "type": "status" in poll branches, got {count}')


async def phase1_broadcast_enrichment_runtime() -> None:
    """Mock WebSocket: broadcast must add scan_id and ts."""
    sys.path.insert(0, str(BACKEND))
    from unittest.mock import AsyncMock, MagicMock

    from app.core.ws_manager import ConnectionManager

    mgr = ConnectionManager()
    ws = MagicMock()
    ws.accept = AsyncMock()
    await mgr.connect(ws, "test-scan-id")
    await mgr.broadcast({"type": "status", "status": "running", "message": "x"}, "test-scan-id")

    ws.send_text.assert_called()
    raw = ws.send_text.call_args[0][0]
    data = json.loads(raw)
    if data.get("scan_id") != "test-scan-id":
        fail(f"runtime broadcast: scan_id mismatch: {data!r}")
    elif "ts" not in data or not data["ts"]:
        fail(f"runtime broadcast: missing ts: {data!r}")
    elif not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", data["ts"]):
        fail(f"runtime broadcast: ts format unexpected: {data['ts']!r}")
    else:
        ok("runtime: ConnectionManager.broadcast enriches with scan_id + UTC ts")


def phase1_enrich_preserves_custom_ts() -> None:
    sys.path.insert(0, str(BACKEND))
    from app.core.ws_manager import enrich_ws_payload

    out = enrich_ws_payload({"type": "status", "ts": "2099-01-01T00:00:00Z"}, "sid")
    if out["ts"] != "2099-01-01T00:00:00Z":
        fail("enrich_ws_payload should preserve existing ts")
    else:
        ok("enrich_ws_payload preserves explicit ts")


def main() -> int:
    print("=== Phase 0 checks (baseline inventory) ===\n")
    phase0_routing_and_health()
    phase0_collections()
    phase0_sample_endpoints()
    phase0_config_settings()
    phase0_doc_exists()

    print("\n=== Phase 1 checks (pipeline + WebSocket contract) ===\n")
    phase1_pipeline_docstring_and_logs()
    phase1_failure_broadcast()
    phase1_ws_manager_enrich()
    phase1_ws_poll_frames()
    phase1_enrich_preserves_custom_ts()
    asyncio.run(phase1_broadcast_enrichment_runtime())

    print("\n=== Phase 2 checks (portfolio) ===\n")
    phase2_portfolio()

    print("\n=== Phase 3 checks (analysis depth) ===\n")
    phase3_analysis_depth()

    print("\n=== Phase 4 checks (policy & integrations) ===\n")
    phase4_policy_integrations()

    print("\n=== Phase 5 checks (migration execution) ===\n")
    phase5_migration_execution()

    print("\n=== Phase 6 checks (executive brief) ===\n")
    phase6_executive_brief()

    print("\n=== Phase 7 checks (ops snapshot) ===\n")
    phase7_ops_snapshot()

    print()
    if FAILURES:
        print(f"Summary: {len(FAILURES)} failure(s)")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("Summary: all Phase 0 through 7 checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
