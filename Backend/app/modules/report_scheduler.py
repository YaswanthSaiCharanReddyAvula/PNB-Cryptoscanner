"""
Background polling for scheduled JSON export bundles + optional SMTP delivery.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.db.connection import get_database
from app.modules.report_bundle import build_export_bundle_payload
from app.modules.report_mail import send_report_email
from app.utils.logger import get_logger

logger = get_logger(__name__)

REPORT_SCHEDULES_COLLECTION = "report_schedules"
MAIL_LOG_COLLECTION = "mail_log"
REPORT_ARTIFACTS_COLLECTION = "report_artifacts"

SCANS_COLLECTION = "scans"
EXPORT_AUDIT_COLLECTION = "export_audit"


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _reports_dir() -> Path:
    d = _backend_root() / settings.GENERATED_REPORTS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def artifact_file_path(filename: str) -> Path:
    """Resolved path for a generated report filename."""
    return _reports_dir() / filename


def compute_next_fire(
    cadence: str,
    hour_utc: int,
    minute_utc: int,
    after: datetime,
) -> datetime:
    """Return next scheduled fire strictly after `after` (naive UTC)."""
    h = max(0, min(23, int(hour_utc)))
    m = max(0, min(59, int(minute_utc)))
    t = after.replace(second=0, microsecond=0)
    if t.tzinfo:
        t = t.replace(tzinfo=None)

    def at_clock(day: datetime) -> datetime:
        return day.replace(hour=h, minute=m, second=0, microsecond=0)

    c = (cadence or "daily").lower()
    if c == "daily":
        cand = at_clock(t)
        if cand <= t:
            cand += timedelta(days=1)
        return cand
    if c == "weekly":
        return at_clock(t + timedelta(days=7))
    if c == "monthly":
        return at_clock(t + timedelta(days=30))
    cand = at_clock(t)
    if cand <= t:
        cand += timedelta(days=1)
    return cand


async def _insert_mail_log(
    db,
    *,
    schedule_id: Optional[str],
    to_addrs: List[str],
    subject: str,
    status: str,
    error: Optional[str] = None,
) -> str:
    log_id = uuid.uuid4().hex
    doc = {
        "log_id": log_id,
        "schedule_id": schedule_id,
        "to": to_addrs,
        "subject": subject,
        "status": status,
        "error": (error or "")[:2000],
        "created_at": datetime.utcnow(),
        "provider": "smtp",
    }
    await db[MAIL_LOG_COLLECTION].insert_one(doc)
    return log_id


async def execute_schedule_run(schedule: Dict[str, Any], *, manual: bool = False) -> None:
    db = get_database()
    sid = schedule.get("schedule_id")
    domain = schedule.get("domain")
    if isinstance(domain, str):
        domain = domain.strip().lower() or None

    delivery = schedule.get("delivery") or {}
    email_enabled = bool(delivery.get("email_enabled"))
    download_enabled = bool(delivery.get("download_enabled"))
    email_to = [str(x).strip() for x in (delivery.get("email_to") or []) if str(x).strip()]

    try:
        payload, scan_doc = await build_export_bundle_payload(db, SCANS_COLLECTION, domain)
    except LookupError:
        err = "No completed scan found for schedule"
        await _insert_mail_log(
            db,
            schedule_id=sid,
            to_addrs=email_to or ["—"],
            subject="QuantumShield scheduled report (failed)",
            status="failed",
            error=err,
        )
        now = datetime.utcnow()
        await db[REPORT_SCHEDULES_COLLECTION].update_one(
            {"schedule_id": sid},
            {
                "$set": {
                    "last_run_at": now,
                    "last_error": err,
                    "next_run_at": compute_next_fire(
                        str(schedule.get("cadence") or "daily"),
                        int(schedule.get("hour_utc") or 6),
                        int(schedule.get("minute_utc") or 0),
                        now,
                    ),
                }
            },
        )
        return

    dom = scan_doc.get("domain") or domain or "latest"
    fname = f"scan_bundle_{dom}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
    artifact_id = uuid.uuid4().hex
    rel_path: Optional[str] = None

    if download_enabled:
        path = _reports_dir() / fname
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        await db[REPORT_ARTIFACTS_COLLECTION].insert_one(
            {
                "artifact_id": artifact_id,
                "schedule_id": sid,
                "domain": dom,
                "filename": fname,
                "created_at": datetime.utcnow(),
            }
        )
        try:
            await db[EXPORT_AUDIT_COLLECTION].insert_one(
                {
                    "event_id": uuid.uuid4().hex,
                    "export_type": "scheduled_scan_bundle_json",
                    "domain": dom,
                    "created_at": datetime.utcnow(),
                    "actor": "scheduler",
                    "artifact_id": artifact_id,
                }
            )
        except Exception as exc:
            logger.warning("Export audit insert failed: %s", exc)

    if email_enabled and email_to:
        subj = f"QuantumShield report — {dom}"
        body = (
            "Attached: scan bundle JSON export from QuantumShield.\n\n"
            f"Domain: {dom}\n"
            f"Schedule: {sid}\n"
            f"Manual run: {manual}\n"
        )
        try:
            await send_report_email(
                email_to,
                subj,
                body,
                fname,
                payload,
            )
            await _insert_mail_log(
                db,
                schedule_id=sid,
                to_addrs=email_to,
                subject=subj,
                status="sent",
            )
        except Exception as exc:
            logger.exception("Email send failed")
            await _insert_mail_log(
                db,
                schedule_id=sid,
                to_addrs=email_to,
                subject=subj,
                status="failed",
                error=str(exc),
            )

    now = datetime.utcnow()
    cadence = str(schedule.get("cadence") or "daily")
    hour_utc = int(schedule.get("hour_utc") or 6)
    minute_utc = int(schedule.get("minute_utc") or 0)
    next_run = compute_next_fire(cadence, hour_utc, minute_utc, now)

    await db[REPORT_SCHEDULES_COLLECTION].update_one(
        {"schedule_id": sid},
        {
            "$set": {
                "last_run_at": now,
                "next_run_at": next_run,
                "last_error": None,
            }
        },
    )


async def scheduler_tick() -> None:
    db = get_database()
    now = datetime.utcnow()
    cursor = db[REPORT_SCHEDULES_COLLECTION].find(
        {"enabled": True, "next_run_at": {"$lte": now}},
    )
    async for sched in cursor:
        try:
            await execute_schedule_run(sched, manual=False)
        except Exception as exc:
            logger.exception("Schedule run failed: %s", exc)
            sid = sched.get("schedule_id")
            if sid:
                await db[REPORT_SCHEDULES_COLLECTION].update_one(
                    {"schedule_id": sid},
                    {"$set": {"last_error": str(exc)[:2000], "last_run_at": datetime.utcnow()}},
                )


async def scheduler_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await scheduler_tick()
        except Exception as exc:
            logger.exception("Scheduler tick failed: %s", exc)
        try:
            await asyncio.wait_for(
                stop.wait(),
                timeout=float(max(5, settings.REPORT_SCHEDULER_POLL_SECONDS)),
            )
        except asyncio.TimeoutError:
            pass
