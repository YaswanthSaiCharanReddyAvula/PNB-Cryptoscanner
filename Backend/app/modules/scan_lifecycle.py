"""
Scan retention (purge old terminal scans) and in-place rescan (reuse Mongo row + scan_id).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.config import settings
from app.db.models import ScanRequest, ScanStatus
from app.modules.report_bundle import domain_match_variants, normalize_host_for_scan_lookup
from app.utils.logger import get_logger

logger = get_logger(__name__)

SCANS_COLLECTION = "scans"

ACTIVE_STATUSES = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)
TERMINAL_STATUSES = (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value)


def normalize_domain_for_scan(raw: str) -> str:
    """Canonical host string for storage and lookup."""
    n = normalize_host_for_scan_lookup(raw)
    return n if n else str(raw).strip().lower()


def variants_for_scan_domain(raw: str) -> List[str]:
    return domain_match_variants(raw)


async def find_active_scan_for_domain(
    collection,
    variants: List[str],
) -> Optional[Dict[str, Any]]:
    if not variants:
        return None
    return await collection.find_one(
        {"domain": {"$in": variants}, "status": {"$in": list(ACTIVE_STATUSES)}},
        sort=[("started_at", -1)],
    )


async def find_reusable_terminal_scan_for_domain(
    collection,
    variants: List[str],
    cutoff_utc: datetime,
) -> Optional[Dict[str, Any]]:
    if not variants:
        return None
    return await collection.find_one(
        {
            "domain": {"$in": variants},
            "status": {"$in": list(TERMINAL_STATUSES)},
            "completed_at": {"$gte": cutoff_utc},
        },
        sort=[("completed_at", -1)],
    )


def _scan_options_from_request(request: ScanRequest) -> Dict[str, Any]:
    scan_opts: Dict[str, Any] = {}
    if request.max_subdomains is not None:
        scan_opts["max_subdomains"] = request.max_subdomains
    if request.execution_time_limit_seconds is not None:
        scan_opts["execution_time_limit_seconds"] = request.execution_time_limit_seconds
    return scan_opts


async def reset_scan_document_for_rerun(
    collection,
    scan_id: str,
    request: ScanRequest,
    *,
    clear_batch_id: bool = False,
) -> None:
    """Clear result fields and return document to pending; same scan_id."""
    d = normalize_domain_for_scan(request.domain)
    scan_opts = _scan_options_from_request(request)

    set_doc: Dict[str, Any] = {
        "status": ScanStatus.PENDING.value,
        "domain": d,
        "started_at": None,
        "completed_at": None,
        "error": None,
        "current_stage": None,
        "progress": None,
        # -- V1 fields --
        "assets": [],
        "tls_results": [],
        "cbom": [],
        "cbom_report": None,
        "quantum_score": None,
        "recommendations": [],
        "headers_results": [],
        "cve_findings": [],
        "vuln_findings": [],
        "dns_records": [],
        # -- V2 engine fields (must clear to avoid stale data) --
        "recon_full": None,
        "subdomains": [],
        "services": [],
        "network_services": [],
        "os_fingerprints": [],
        "cdn_waf_intel": [],
        "tech_fingerprints": [],
        "web_profiles": [],
        "hidden_findings": [],
        "infrastructure_intel": None,
        "all_findings": [],
        "graph": None,
        "risk_scores": [],
        "executive_summary": "",
        "estate_tier": None,
        "stages": [],
        "stage_metrics": [],
    }
    if scan_opts:
        set_doc["scan_options"] = scan_opts
    else:
        set_doc["scan_options"] = None

    update: Dict[str, Any] = {"$set": set_doc}
    unset_keys: List[str] = []
    if clear_batch_id:
        unset_keys.append("batch_id")
    if unset_keys:
        update["$unset"] = {k: "" for k in unset_keys}

    await collection.update_one({"scan_id": scan_id}, update)


async def purge_expired_scans(db, scans_collection: str = SCANS_COLLECTION) -> int:
    """
    Delete terminal scans with completed_at older than SCAN_RETENTION_DAYS.
    Returns deleted count (best-effort; may be -1 if unavailable).
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=max(1, settings.SCAN_RETENTION_DAYS))
        result = await db[scans_collection].delete_many(
            {
                "status": {"$in": list(TERMINAL_STATUSES)},
                "completed_at": {"$lt": cutoff},
            }
        )
        n = int(result.deleted_count)
        if n:
            logger.info("Scan retention purge removed %d terminal scan document(s) older than %s", n, cutoff.isoformat())
        return n
    except Exception as exc:
        logger.warning("Scan retention purge failed: %s", exc)
        return -1


async def ensure_scan_indexes(db, scans_collection: str = SCANS_COLLECTION) -> None:
    """Idempotent indexes for domain + status / completed_at lookups."""
    coll = db[scans_collection]
    try:
        await coll.create_index([("domain", 1), ("status", 1)], name="domain_status_1")
        await coll.create_index([("domain", 1), ("completed_at", -1)], name="domain_completed_at_1")
        await coll.create_index([("status", 1), ("completed_at", 1)], name="status_completed_at_1")
    except Exception as exc:
        logger.warning("Could not ensure scan indexes: %s", exc)
