"""Consistent asset classification from open ports (dashboard KPIs, distribution, inventory TYPE)."""

from __future__ import annotations

from typing import Iterable, Set

WEB_PORTS = frozenset({80, 443, 8080, 8443})
SERVER_PORTS = frozenset({22, 21, 3306, 5432, 3389})


def classify_asset_service(
    services: list[dict] | None = None,
) -> str:
    """
    Classify an asset using V2 service fingerprints.
    
    Returns slug: 'web_app' | 'mail_server' | 'database' | 
                  'dns_server' | 'remote_access' | 'api'
    """
    categories = set()
    
    for svc in (services or []):
        cat = (svc.get("protocol_category") or "").lower()
        if cat:
            categories.add(cat)
            
    if "web" in categories:
        return "web_app"
    if "mail" in categories:
        return "mail_server"
    if "db" in categories:
        return "database"
    if "dns" in categories:
        return "dns_server"
    if "remote" in categories:
        return "remote_access"
        
    return "api"


_LABELS = {
    "web_app": "Web Application",
    "mail_server": "Mail Server", 
    "database": "Database",
    "dns_server": "DNS Server",
    "remote_access": "Remote Access",
    "server": "Server",
    "api": "API Service",
}


def asset_type_label(slug: str) -> str:
    return _LABELS.get(slug, "Unknown")
