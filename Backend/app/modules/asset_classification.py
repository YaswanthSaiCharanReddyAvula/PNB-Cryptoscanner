"""
Derive asset buckets (hosting, surface, mobile gateways) from ports, TLS, HTTP headers, and light probes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.db.models import DiscoveredAsset, HeadersResult, TLSInfo
from app.config import settings
from app.utils.asset_type import classify_asset_ports

logger = logging.getLogger(__name__)

MAIL_PORTS = frozenset({25, 465, 587, 993, 995, 143})
VPN_PORTS = frozenset({1194, 500, 4500, 1701})
RDP_PORTS = frozenset({3389})

# Hostname tokens suggesting SaaS / third-party hosting
_SAAS_HOST_TOKENS = (
    "shopify",
    "myshopify",
    "azurewebsites",
    "cloudapp",
    "vercel",
    "netlify",
    "github.io",
    "herokuapp",
    "salesforce",
    "force.com",
    "zendesk",
    "atlassian",
    "jira.com",
    "freshdesk",
    "hubspot",
    "squarespace",
    "wix.com",
    "wordpress.com",
    "bigcartel",
)

_CDN_HEADER_MARKERS = (
    "cloudflare",
    "akamai",
    "cloudfront",
    "fastly",
    "incapsula",
    "keycdn",
    "stackpath",
)


def _surface_from_ports(ports: List[int]) -> str:
    p: set[int] = set()
    for x in ports or []:
        try:
            p.add(int(x))
        except (TypeError, ValueError):
            continue
    if p & MAIL_PORTS:
        return "mail"
    if p & VPN_PORTS:
        return "vpn"
    if p & RDP_PORTS:
        return "rdp"
    slug = classify_asset_ports(list(p))
    if slug == "web_app":
        return "web"
    if slug == "api":
        return "api"
    return "unknown"


def _host_under_root(host: str, root: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    r = (root or "").strip().lower().rstrip(".")
    if not h or not r:
        return False
    return h == r or h.endswith("." + r)


def _pick_tls_for_host(tls_results: List[TLSInfo], host: str) -> Optional[TLSInfo]:
    rows = [t for t in tls_results if (t.host or "").strip().lower() == (host or "").strip().lower()]
    if not rows:
        return None
    rows.sort(key=lambda t: (0 if t.port == 443 else 1, t.port))
    return rows[0]


def _header_value_from_findings(hr: Optional[HeadersResult], header_name: str) -> Optional[str]:
    if not hr or not hr.findings:
        return None
    for f in hr.findings:
        if f.header.lower() == header_name.lower() and f.present and f.value:
            return f.value
    return None


def _tls_reachability(tls: Optional[TLSInfo]) -> str:
    if not tls:
        return "no_tls_scan"
    if tls.error:
        return "tls_error"
    if tls.tls_version:
        return "scannable_tls"
    return "unknown_tls"


async def probe_http_metadata(host: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    timeout = max(3.0, float(settings.CLASSIFICATION_PROBE_TIMEOUT))
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            r = await client.get(url, timeout=timeout)
            out["http_status"] = r.status_code
            out["final_url"] = str(r.url)
            h = {k.lower(): v for k, v in r.headers.items()}
            out["server"] = h.get("server")
            out["via"] = h.get("via")
            out["cf_ray"] = h.get("cf-ray")
            out["x_served_by"] = h.get("x-served-by")
            out["x_cache"] = h.get("x-cache")
            return out
        except Exception as e:
            logger.debug("probe %s %s: %s", scheme, host, e)
            continue
    return out


async def probe_mobile_well_known(host: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    timeout = max(3.0, min(float(settings.CLASSIFICATION_PROBE_TIMEOUT), 12.0))
    result = {"apple_aasa": False, "android_assetlinks": False}
    paths = (
        ("/.well-known/apple-app-site-association", "apple_aasa"),
        ("/.well-known/assetlinks.json", "android_assetlinks"),
    )
    for path, key in paths:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}{path}", timeout=timeout)
                if r.status_code == 200 and len((r.text or "").strip()) > 20:
                    result[key] = True
                    break
            except Exception:
                continue
    return result


def _infer_hosting_hint(
    host: str,
    scan_root: str,
    http_meta: Dict[str, Any],
    tls: Optional[TLSInfo],
) -> Tuple[str, List[str]]:
    """Return (hosting_hint, extra_bucket_tags)."""
    buckets: List[str] = []
    h = (host or "").lower()
    root = (scan_root or "").lower()

    if _host_under_root(host, scan_root):
        hint = "first_party"
        buckets.append("first_party")
    else:
        hint = "unknown"
        buckets.append("external_hostname")

    for tok in _SAAS_HOST_TOKENS:
        if tok in h:
            hint = "saas_likely"
            buckets.append("saas_likely")
            break

    server = (http_meta.get("server") or "") + " " + (http_meta.get("via") or "")
    server_l = server.lower()
    for m in _CDN_HEADER_MARKERS:
        if m in server_l:
            if hint == "first_party":
                hint = "third_party_cdn"
            elif hint == "unknown":
                hint = "third_party_cdn"
            buckets.append("third_party_cdn")
            break

    if http_meta.get("cf_ray"):
        buckets.append("cdn_cloudflare_signal")
        if hint in ("first_party", "unknown"):
            hint = "third_party_cdn"

    cert_sub = ""
    if tls and tls.certificate and tls.certificate.subject:
        cert_sub = str(tls.certificate.subject).lower()
    if any(x in cert_sub for x in ("amazon", "cloudfront", "microsoft", "azure")):
        buckets.append("cloud_provider_cert_signal")
        if hint == "first_party":
            hint = "cloud_provider"

    if hint == "unknown" and not buckets:
        buckets.append("hosting_unclassified")

    return hint, buckets


def _classify_one_asset(
    asset: DiscoveredAsset,
    tls: Optional[TLSInfo],
    headers: Optional[HeadersResult],
    http_meta: Dict[str, Any],
    mobile: Dict[str, Any],
    scan_root: str,
) -> DiscoveredAsset:
    ports = list(asset.open_ports or [])
    surface = _surface_from_ports(ports)
    reach = _tls_reachability(tls)

    hosting_hint, host_buckets = _infer_hosting_hint(asset.subdomain, scan_root, http_meta, tls)

    buckets: List[str] = list(dict.fromkeys(host_buckets))
    buckets.append(f"surface:{surface}")
    buckets.append(f"reachability:{reach}")

    if mobile.get("apple_aasa"):
        buckets.append("mobile_universal_links")
    if mobile.get("android_assetlinks"):
        buckets.append("mobile_app_links")

    if surface == "web" and (mobile.get("apple_aasa") or mobile.get("android_assetlinks")):
        buckets.append("mobile_gateway_host")

    # Server header from headers scan (forbidden-header finding) if probe missed
    srv_finding = _header_value_from_findings(headers, "Server")
    attrs: Dict[str, Any] = {
        "tls_version": tls.tls_version if tls else None,
        "tls_port": tls.port if tls else None,
        "http_probe_server": http_meta.get("server"),
        "http_probe_via": http_meta.get("via"),
        "headers_scan_server": srv_finding,
        "apple_aasa": mobile.get("apple_aasa"),
        "android_assetlinks": mobile.get("android_assetlinks"),
        "classification_version": 1,
    }

    return asset.model_copy(
        update={
            "buckets": list(dict.fromkeys(buckets)),
            "hosting_hint": hosting_hint,
            "surface": surface,
            "classification_attributes": attrs,
        }
    )


async def enrich_discovered_assets(
    assets: List[DiscoveredAsset],
    tls_results: List[TLSInfo],
    headers_results: List[HeadersResult],
    scan_root_domain: str,
) -> List[DiscoveredAsset]:
    """
    Async enrichment: HTTP probes (limited concurrency) for hosts with 80/443, then classify all.
    """
    if not assets:
        return []

    headers_by_host = {(h.host or "").strip().lower(): h for h in headers_results if h.host}

    webish = [
        a
        for a in assets
        if (80 in (a.open_ports or []) or 443 in (a.open_ports or []))
    ]
    max_probe = min(len(webish), int(settings.CLASSIFICATION_MAX_HTTP_PROBES))
    probe_targets = webish[:max_probe]
    probe_set = {a.subdomain.lower() for a in probe_targets}

    meta_by_host: Dict[str, Dict[str, Any]] = {}
    mobile_by_host: Dict[str, Dict[str, Any]] = {}

    sem = asyncio.Semaphore(8)

    async def probe_pair(a: DiscoveredAsset) -> None:
        host = a.subdomain
        key = host.lower()
        async with sem:
            try:
                timeout = httpx.Timeout(max(3.0, float(settings.CLASSIFICATION_PROBE_TIMEOUT)))
                async with httpx.AsyncClient(
                    verify=False,
                    follow_redirects=True,
                    timeout=timeout,
                    headers={"User-Agent": "QuantumShield-AssetClassifier/1.0"},
                ) as client:
                    meta_by_host[key] = await probe_http_metadata(host, client)
                    mobile_by_host[key] = await probe_mobile_well_known(host, client)
            except Exception as e:
                logger.warning("classification probe failed for %s: %s", host, e)
                meta_by_host[key] = {}
                mobile_by_host[key] = {"apple_aasa": False, "android_assetlinks": False}

    await asyncio.gather(*[probe_pair(a) for a in probe_targets])

    out: List[DiscoveredAsset] = []
    for a in assets:
        key = a.subdomain.lower()
        tls = _pick_tls_for_host(tls_results, a.subdomain)
        hr = headers_by_host.get(key)
        meta = meta_by_host.get(key, {})
        mob = mobile_by_host.get(key, {"apple_aasa": False, "android_assetlinks": False})
        if key not in probe_set:
            meta = {}
            mob = {"apple_aasa": False, "android_assetlinks": False}
        out.append(_classify_one_asset(a, tls, hr, meta, mob, scan_root_domain))

    return out
