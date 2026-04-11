"""SMTP email with JSON attachment for scheduled reports."""

from __future__ import annotations

import json
from email.message import EmailMessage
from typing import Any, List

import aiosmtplib

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def send_report_email(
    to_addrs: List[str],
    subject: str,
    body_text: str,
    attachment_name: str,
    attachment_obj: Any,
) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        raise RuntimeError("SMTP not configured (SMTP_HOST / SMTP_FROM)")

    raw = json.dumps(attachment_obj, indent=2, default=str).encode("utf-8")
    max_mb = max(1, int(settings.REPORT_MAX_ATTACHMENT_MB))
    if len(raw) > max_mb * 1024 * 1024:
        raise RuntimeError(f"Report JSON exceeds REPORT_MAX_ATTACHMENT_MB ({max_mb})")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body_text)
    msg.add_attachment(
        raw,
        maintype="application",
        subtype="json",
        filename=attachment_name,
    )

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=int(settings.SMTP_PORT),
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_USE_TLS,
    )
    logger.info("Sent report email to %s", to_addrs)
