"""
QuantumShield — CDN / WAF / Proxy Detection Engine (Stage 6)

Identifies CDN, WAF, reverse proxy, and cloud provider from DNS
CNAME chains, HTTP response headers, and ASN mapping.  No external
tools — pure httpx + dnspython.
"""

from __future__ import annotations

import re

import httpx

from app.scanner.models import InfrastructureIntel, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

CDN_CNAME_PATTERNS: list[tuple[str, str]] = [
    (r"\.cloudfront\.net$",       "AWS CloudFront"),
    (r"\.cdn\.cloudflare\.net$",  "Cloudflare"),
    (r"\.cloudflare\.net$",       "Cloudflare"),
    (r"\.akamaiedge\.net$",       "Akamai"),
    (r"\.akadns\.net$",           "Akamai"),
    (r"\.fastly\.net$",           "Fastly"),
    (r"\.azureedge\.net$",        "Azure CDN"),
    (r"\.stackpathdns\.com$",     "StackPath"),
    (r"\.incapdns\.net$",         "Imperva/Incapsula"),
    (r"\.sucuri\.net$",           "Sucuri"),
]

CDN_HEADER_SIGS: list[tuple[str, str, str]] = [
    ("cf-ray",                    "",                 "Cloudflare"),
    ("x-amz-cf-id",              "",                 "AWS CloudFront"),
    ("x-served-by",              "",                 "Fastly/Varnish"),
    ("x-cache",                   r"HIT from cloudfront", "AWS CloudFront"),
    ("server",                    r"^cloudflare$",    "Cloudflare"),
    ("x-cdn",                     "",                 "Generic CDN"),
    ("x-sucuri-id",              "",                 "Sucuri"),
]

WAF_HEADER_SIGS: list[tuple[str, str, str]] = [
    ("cf-chl-bypass",            "",                 "Cloudflare WAF"),
    ("x-amzn-waf-action",       "",                 "AWS WAF"),
    ("server",                    r"AkamaiGHost",    "Akamai WAF"),
    ("x-sucuri-id",              "",                 "Sucuri WAF"),
]

WAF_BODY_SIGS: list[tuple[str, str]] = [
    (r"Attention Required.*Cloudflare",  "Cloudflare WAF"),
    (r"ModSecurity",                     "ModSecurity"),
    (r"Access Denied.*Imperva",          "Imperva WAF"),
    (r"<title>Blocked</title>",          "Generic WAF"),
]

CLOUD_ASN_MAP: dict[str, str] = {
    "16509": "AWS", "14618": "AWS",
    "8075": "Azure",
    "15169": "GCP", "396982": "GCP",
    "13335": "Cloudflare",
    "20940": "Akamai",
    "54113": "Fastly",
}


class CDNWAFEngine(ScanStage):
    name = "cdn_waf"
    order = 6
    timeout_seconds = 45
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["cdn_waf_intel"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        results: list[dict] = []
        request_count = 0

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
            for host in (ctx.subdomains or [])[:50]:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        intel, reqs = await self._analyse(client, host, ctx)
                        results.append(intel.model_dump())
                        request_count += reqs
                except Exception:
                    logger.warning("CDN/WAF analysis failed for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"cdn_waf_intel": results},
            request_count=request_count,
        )

    async def _analyse(self, client: httpx.AsyncClient, host: str, ctx: ScanContext):
        cdn_provider = None
        cdn_ev: list[str] = []
        waf_detected = False
        waf_provider = None
        waf_ev: list[str] = []
        proxy = None
        cloud = None
        cloud_ev: list[str] = []
        reqs = 0

        import dns.asyncresolver
        try:
            async with ctx.throttle.acquire("dns"):
                ans = await dns.asyncresolver.resolve(host, "CNAME")
                for rdata in ans:
                    cname = str(rdata.target).rstrip(".")
                    for pat, name in CDN_CNAME_PATTERNS:
                        if re.search(pat, cname, re.IGNORECASE):
                            cdn_provider = name
                            cdn_ev.append(f"CNAME {cname}")
                            break
        except Exception:
            pass

        try:
            resp_clean = await client.get(f"https://{host}/")
            reqs += 1
            hdrs = {k.lower(): v for k, v in resp_clean.headers.items()}

            for hdr, pat, name in CDN_HEADER_SIGS:
                val = hdrs.get(hdr, "")
                if val and (not pat or re.search(pat, val, re.IGNORECASE)):
                    if not cdn_provider:
                        cdn_provider = name
                    cdn_ev.append(f"header {hdr}: {val[:80]}")

            for hdr, pat, name in WAF_HEADER_SIGS:
                val = hdrs.get(hdr, "")
                if val and (not pat or re.search(pat, val, re.IGNORECASE)):
                    waf_detected = True
                    waf_provider = name
                    waf_ev.append(f"header {hdr}: {val[:80]}")

            if hdrs.get("via"):
                proxy = hdrs["via"][:120]

            resp_mal = await client.get(
                f"https://{host}/?test=%3Cscript%3Ealert(1)%3C/script%3E"
            )
            reqs += 1
            if resp_clean.status_code == 200 and resp_mal.status_code in (403, 406, 429):
                waf_detected = True
                if not waf_provider:
                    waf_provider = "Unknown WAF"
                waf_ev.append(f"clean=200 vs malicious={resp_mal.status_code}")
                body = resp_mal.text[:2000]
                for pat, name in WAF_BODY_SIGS:
                    if re.search(pat, body, re.IGNORECASE):
                        waf_provider = name
                        break

        except Exception:
            pass

        asn_str = None
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            if s.get("host") == host:
                asn_str = (s.get("asn") or {}).get("asn") if isinstance(s.get("asn"), dict) else None
                break
        if not asn_str:
            ips = (ctx.ip_map or {}).get(host, [])
            if ips:
                for svc in (ctx.services or []):
                    s = svc if isinstance(svc, dict) else {}
                    if s.get("host") in ips:
                        asn_str = (s.get("asn") or {}).get("asn") if isinstance(s.get("asn"), dict) else None
                        if asn_str:
                            break

        if asn_str and str(asn_str).strip() in CLOUD_ASN_MAP:
            cloud = CLOUD_ASN_MAP[str(asn_str).strip()]
            cloud_ev.append(f"ASN {asn_str}")

        return InfrastructureIntel(
            host=host,
            cdn_provider=cdn_provider,
            cdn_evidence=cdn_ev,
            waf_detected=waf_detected,
            waf_provider=waf_provider,
            waf_evidence=waf_ev,
            reverse_proxy=proxy,
            cloud_provider=cloud,
            cloud_evidence=cloud_ev,
        ), reqs
