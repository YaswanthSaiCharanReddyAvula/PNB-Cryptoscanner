"""Consistent asset classification from open ports (dashboard KPIs, distribution, inventory TYPE)."""

from __future__ import annotations

from typing import Iterable, Set

WEB_PORTS = frozenset({80, 443, 8080, 8443})
SERVER_PORTS = frozenset({22, 21, 3306, 5432, 3389})


def classify_asset_ports(ports: Iterable[int] | None) -> str:
    """
    Return slug: 'web_app' | 'server' | 'api'.
    Web-facing ports win; then infra / remote-admin / DB ports; else API or unknown service.
    """
    p: Set[int] = set()
    for x in ports or []:
        try:
            p.add(int(x))
        except (TypeError, ValueError):
            continue
    if p & WEB_PORTS:
        return "web_app"
    if p & SERVER_PORTS:
        return "server"
    return "api"


def asset_type_label(slug: str) -> str:
    return {"web_app": "Web App", "server": "Server", "api": "API"}.get(slug, "Unknown")
