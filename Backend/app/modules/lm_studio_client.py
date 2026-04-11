"""
OpenAI-compatible chat completions (LM Studio, etc.) via HTTP.
"""

from __future__ import annotations

from typing import Any, List, Optional

import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def chat_completion(
    messages: List[dict[str, Any]],
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> str:
    """POST to OpenAI-compatible chat completions URL; returns assistant message content or raises."""
    url = settings.llm_chat_completions_url
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.LLM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"

    payload = {
        "model": settings.LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    timeout = httpx.Timeout(settings.LLM_TIMEOUT_SECONDS)
    # trust_env=False: do not send local LM requests through HTTP_PROXY (common cause of
    # "All connection attempts failed" when the proxy cannot reach 127.0.0.1 / LAN IPs).
    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=settings.LLM_TRUST_ENV,
    ) as client:
        r = await client.post(url, json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("LLM response missing choices")
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return content.strip()
    raise RuntimeError("LLM response missing message content")


async def chat_completion_safe(
    messages: List[dict[str, Any]],
    fallback: str,
) -> str:
    try:
        return await chat_completion(messages)
    except Exception as exc:
        url = settings.llm_chat_completions_url
        logger.warning(
            "LLM call failed (%s): model=%r url=%s — if this is a connection error, "
            "confirm LM Studio is running, the URL is reachable from this machine, "
            "and that LLM_TRUST_ENV=false avoids an unwanted HTTP_PROXY (set LLM_TRUST_ENV=true only if you need a proxy).",
            exc,
            settings.LLM_MODEL,
            url,
        )
        return fallback
