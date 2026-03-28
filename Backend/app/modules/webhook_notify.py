"""Fire-and-forget outbound webhooks (Phase 4 integrations)."""

from __future__ import annotations

import httpx

from app.utils.logger import get_logger

logger = get_logger(__name__)


async def post_json_webhook(url: str, payload: dict) -> None:
    """POST JSON to a user-configured URL; failures are logged, not raised."""
    u = (url or "").strip()
    if not u:
        return
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            r = await client.post(u, json=payload)
            r.raise_for_status()
        except Exception as exc:
            logger.warning("Outbound webhook POST failed (%s): %s", u[:48], exc)


async def post_slack_incoming_webhook(url: str, text: str) -> None:
    """POST Slack-compatible {text: ...} payload to an incoming webhook URL."""
    u = (url or "").strip()
    if not u:
        return
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            r = await client.post(u, json={"text": text})
            r.raise_for_status()
        except Exception as exc:
            logger.warning("Slack webhook POST failed (%s): %s", u[:48], exc)
