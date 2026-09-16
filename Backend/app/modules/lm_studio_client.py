"""
OpenAI-compatible chat completions (LM Studio, etc.) via HTTP.

This client connects to a locally-hosted, privacy-preserving AI model.
No data leaves your network — all inference runs on infrastructure you control.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, List, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── SSRF protection ──────────────────────────────────────────────

# Cloud metadata endpoints that must never be reachable via the LLM client.
_BLOCKED_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
}

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _parse_cidr_or_host(entry: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network | str]:
    """Parse a single LLM_ALLOWED_HOSTS entry as a CIDR network or plain hostname."""
    entry = entry.strip()
    if not entry:
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return entry  # Plain hostname like "localhost"


def _is_allowed_host(hostname: str) -> bool:
    """Check if *hostname* is permitted by LLM_ALLOWED_HOSTS (SSRF guard)."""
    allowed_raw = settings.LLM_ALLOWED_HOSTS.strip()
    if allowed_raw == "*":
        return True

    entries = [_parse_cidr_or_host(e) for e in allowed_raw.split(",")]

    # Check plain hostname match
    for e in entries:
        if isinstance(e, str) and e.lower() == hostname.lower():
            return True

    # Resolve to IP and check CIDR ranges
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = {info[4][0] for info in resolved}
    except (socket.gaierror, OSError):
        ips = set()

    for ip_str in ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for e in entries:
            if isinstance(e, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if addr in e:
                    return True

    return False


def _validate_llm_url(url: str) -> None:
    """Validate the LLM URL is safe (not an SSRF target)."""
    parsed = urlparse(url)

    # Only allow HTTP/HTTPS schemes
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"LLM URL uses disallowed scheme '{parsed.scheme}' — "
            f"only http:// and https:// are permitted."
        )

    hostname = parsed.hostname or ""

    # Block cloud metadata endpoints
    if hostname in _BLOCKED_IPS:
        raise ValueError(
            f"LLM URL targets a blocked metadata endpoint ({hostname}). "
            f"This looks like an SSRF attempt."
        )

    # Check against allowlist
    if not _is_allowed_host(hostname):
        logger.warning(
            "LLM URL host '%s' is not in LLM_ALLOWED_HOSTS (%s). "
            "If this is intentional, add the host to LLM_ALLOWED_HOSTS in .env.",
            hostname,
            settings.LLM_ALLOWED_HOSTS,
        )
        raise ValueError(
            f"LLM URL host '{hostname}' is not in the allowed hosts list. "
            f"Update LLM_ALLOWED_HOSTS in .env to permit this host."
        )


# ── LLM health check ────────────────────────────────────────────

async def check_llm_health() -> dict:
    """Quick connectivity check against the configured LLM endpoint.

    Returns a dict with 'available' (bool), 'model', and 'url' (masked).
    """
    url = settings.llm_chat_completions_url
    masked = url[:20] + "…" + url[-4:] if len(url) > 24 else "****"
    try:
        _validate_llm_url(url)
    except ValueError as ve:
        return {
            "available": False,
            "model": settings.LLM_MODEL,
            "url": masked,
            "error": str(ve),
        }

    # Try a lightweight GET to the base /v1/models endpoint
    models_url = url.replace("/chat/completions", "/models")
    timeout = httpx.Timeout(5.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            trust_env=settings.LLM_TRUST_ENV,
        ) as client:
            r = await client.get(models_url)
            return {
                "available": r.status_code < 500,
                "model": settings.LLM_MODEL,
                "url": masked,
            }
    except Exception as exc:
        return {
            "available": False,
            "model": settings.LLM_MODEL,
            "url": masked,
            "error": f"Connection failed: {type(exc).__name__}",
        }


# ── Chat completion ──────────────────────────────────────────────

async def chat_completion(
    messages: List[dict[str, Any]],
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> str:
    """POST to OpenAI-compatible chat completions URL; returns assistant message content or raises."""
    url = settings.llm_chat_completions_url

    # SSRF guard
    _validate_llm_url(url)

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
