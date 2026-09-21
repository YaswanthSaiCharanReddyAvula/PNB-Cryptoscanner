"""
QuantumShield — Technology Fingerprint Engine (Stage 7)

Wappalyzer-style detection of web servers, languages, frameworks,
CMS, JS libraries, and analytics from HTTP responses.  No external
tools — pure httpx + regex.

Changes from baseline:
  - Runtime detection (PHP, Python, Java, etc.) migrated here from OS engine
  - In-memory deduplication: multiple evidence vectors for the same technology
    are merged into a single TechFingerprint with combined evidence_sources
  - HTTP response caching via ctx.http_cache to avoid redundant requests
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

import httpx

from app.scanner.models import StageResult, TechFingerprint
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

COOKIE_RUNTIME_MAP: dict[str, tuple[str, str]] = {
    "JSESSIONID":         ("language", "Java"),
    "PHPSESSID":          ("language", "PHP"),
    "ASP.NET_SessionId":  ("language", ".NET"),
    "connect.sid":        ("framework", "Express/Node.js"),
    "laravel_session":    ("framework", "Laravel"),
    "csrftoken":          ("framework", "Django"),
    "_rails_session":     ("framework", "Ruby on Rails"),
}

ERROR_PAGE_SIGS: list[tuple[str, str, str]] = [
    (r"Whitelabel Error Page",         "framework", "Spring Boot"),
    (r"Django Version:",               "framework", "Django"),
    (r"Traceback \(most recent call",  "language",  "Python"),
    (r"<b>Fatal error</b>.*PHP",       "language",  "PHP"),
    (r"Microsoft .NET Framework.*Error", "language", ".NET"),
    (r"Ruby on Rails",                 "framework", "Ruby on Rails"),
    (r"Express.*Error",                "framework", "Express"),
]

# Runtime patterns migrated from OSFingerprintEngine — these are
# application-layer technologies, not OS indicators.
BANNER_RUNTIME_SIGS: list[tuple[str, str, str]] = [
    (r"PHP/([\d.]+)",              "language",  "PHP"),
    (r"Express",                   "framework", "Express/Node.js"),
    (r"ASP\.NET",                  "language",  ".NET"),
    (r"Werkzeug|gunicorn|uvicorn", "language",  "Python"),
    (r"Servlet",                   "language",  "Java"),
]

_sig_cache: Optional[list[dict]] = None


def _load_signatures() -> list[dict]:
    global _sig_cache
    if _sig_cache is not None:
        return _sig_cache
    path = _DATA_DIR / "tech_signatures.json"
    if path.is_file():
        try:
            _sig_cache = json.loads(path.read_text(encoding="utf-8"))
            return _sig_cache
        except Exception:
            logger.warning("Failed to load tech_signatures.json", exc_info=True)
    _sig_cache = []
    return _sig_cache


# ── Confidence aggregation ────────────────────────────────────────────

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def _best_confidence(*confs: str) -> str:
    """Return the highest confidence level from a set of values."""
    best = 0
    for c in confs:
        best = max(best, _CONF_RANK.get(c, 0))
    return {3: "high", 2: "medium"}.get(best, "low")


# ── Deduplication helper ──────────────────────────────────────────────

class _TechAccumulator:
    """Accumulates evidence for unique (host, name, category) keys."""

    def __init__(self):
        self._map: dict[str, dict[str, Any]] = {}

    def _key(self, host: str, name: str, category: str) -> str:
        return f"{host}||{name.lower().strip()}||{category.lower().strip()}"

    def add(
        self,
        host: str,
        category: str,
        name: str,
        *,
        version: str | None = None,
        confidence: str = "medium",
        evidence: str = "",
        cpe: str | None = None,
    ) -> None:
        key = self._key(host, name, category)
        if key in self._map:
            existing = self._map[key]
            # Merge evidence
            if evidence and evidence not in existing["evidence_sources"]:
                existing["evidence_sources"].append(evidence)
            # Keep most specific version
            if version and not existing["version"]:
                existing["version"] = version
            # Upgrade confidence
            existing["confidence"] = _best_confidence(
                existing["confidence"], confidence
            )
            # Keep CPE if we get one
            if cpe and not existing["cpe"]:
                existing["cpe"] = cpe
        else:
            self._map[key] = {
                "host": host,
                "category": category,
                "name": name,
                "version": version,
                "confidence": confidence,
                "evidence_sources": [evidence] if evidence else [],
                "cpe": cpe,
            }

    def results(self) -> list[dict]:
        """Return deduplicated TechFingerprint dicts."""
        out: list[dict] = []
        for entry in self._map.values():
            ev_list = entry["evidence_sources"]
            out.append(TechFingerprint(
                host=entry["host"],
                category=entry["category"],
                name=entry["name"],
                version=entry["version"],
                confidence=entry["confidence"],
                evidence="; ".join(ev_list) if ev_list else None,
                evidence_sources=ev_list,
                cpe=entry["cpe"],
            ).model_dump())
        return out


class TechFingerprintEngine(ScanStage):
    name = "tech_fingerprint"
    order = 7
    timeout_seconds = 45
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["tech_fingerprints"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        request_count = 0
        sigs = _load_signatures()
        if not sigs:
            logger.warning(
                "TechFingerprintEngine: signature database is empty — "
                "operating in degraded mode"
            )

        acc = _TechAccumulator()
        web_hosts = self._web_hosts(ctx)

        # ── Phase A: Extract runtime hints from existing service banners ──
        self._extract_banner_runtimes(ctx, acc)

        # ── Phase B: Active HTTP fingerprinting per host ──
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10.0
        ) as client:
            for host in web_hosts:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        reqs = await self._fingerprint_host(
                            client, host, sigs, ctx, acc,
                        )
                        request_count += reqs
                except Exception:
                    logger.warning("Tech FP failed for %s", host, exc_info=True)

        results = acc.results()

        logger.info(
            "TechFingerprintEngine complete — %d hosts, %d technologies, %d requests",
            len(web_hosts), len(results), request_count,
        )

        return StageResult(
            status="completed",
            data={"tech_fingerprints": results},
            request_count=request_count,
        )

    # ── Banner runtime extraction (migrated from OS engine) ───────────

    @staticmethod
    def _extract_banner_runtimes(
        ctx: ScanContext, acc: _TechAccumulator
    ) -> None:
        """Detect application runtimes from service banners already in ctx.services."""
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            banner = s.get("raw_banner") or ""
            host = s.get("host", "")
            if not banner or not host:
                continue
            for pattern, category, name in BANNER_RUNTIME_SIGS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    acc.add(
                        host=host,
                        category=category,
                        name=name,
                        version=version,
                        confidence="medium",
                        evidence=f"service_banner: {pattern[:40]}",
                    )

    @staticmethod
    def _web_hosts(ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else (svc.model_dump() if hasattr(svc, 'model_dump') else {})
            if s.get("protocol_category") == "web" or s.get("port") in (80, 443, 8080, 8443):
                h = s.get("host", "")
                if h and h not in hosts:
                    hosts.append(h)
        if not hosts:
            hosts = list(ctx.subdomains or [])
        return hosts

    # ── HTTP cache helpers ────────────────────────────────────────────

    @staticmethod
    async def _fetch_or_cache(
        client: httpx.AsyncClient,
        url: str,
        ctx: ScanContext,
    ) -> tuple[httpx.Response | None, bool]:
        """Fetch a URL, using ctx.http_cache to avoid duplicate requests.

        Returns (response, was_cached). Response is None on failure.
        """
        cache = getattr(ctx, "http_cache", None)
        if cache is None:
            cache = {}
            ctx.http_cache = cache

        if url in cache:
            return cache[url], True

        try:
            resp = await client.get(url)
            cache[url] = resp
            return resp, False
        except httpx.ConnectError:
            # Try HTTP fallback for HTTPS URLs
            if url.startswith("https://"):
                http_url = "http://" + url[8:]
                try:
                    resp = await client.get(http_url)
                    cache[url] = resp
                    return resp, False
                except Exception:
                    return None, False
            return None, False
        except Exception:
            return None, False

    async def _fingerprint_host(self, client, host, sigs, ctx, acc):
        reqs = 0

        # ── Root page ──
        root_url = f"https://{host}/"
        resp, was_cached = await self._fetch_or_cache(client, root_url, ctx)
        if not was_cached and resp is not None:
            reqs += 1
        if resp is None:
            return reqs

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:65536]
        hdr_str = str(hdrs)

        # ── Signature matching ──
        for sig in sigs:
            for match_rule in sig.get("matches", []):
                mtype = match_rule.get("type", "")
                pat = match_rule.get("pattern", "")
                if not pat:
                    continue
                source = hdr_str if mtype == "header" else body if mtype in ("html", "script") else str(resp.cookies)
                m = re.search(pat, source, re.IGNORECASE)
                if m:
                    ver = None
                    vg = match_rule.get("version_group")
                    if vg is not None and m.lastindex and vg <= m.lastindex:
                        ver = m.group(vg)
                    cpe = None
                    cpe_tpl = sig.get("cpe_template")
                    if cpe_tpl and ver:
                        cpe = cpe_tpl.replace("{version}", ver)
                    acc.add(
                        host=host,
                        category=sig.get("category", "unknown"),
                        name=sig.get("name", "unknown"),
                        version=ver,
                        confidence=match_rule.get("confidence", "medium"),
                        evidence=f"{mtype} match: {pat[:60]}",
                        cpe=cpe,
                    )
                    break  # first match per signature is sufficient

        # ── Cookie detection ──
        for cookie_name, (cat, tech) in COOKIE_RUNTIME_MAP.items():
            if cookie_name.lower() in str(resp.cookies).lower():
                acc.add(
                    host=host,
                    category=cat,
                    name=tech,
                    confidence="medium",
                    evidence=f"cookie {cookie_name}",
                )

        # ── Error page detection ──
        try:
            async with ctx.throttle.acquire("http_probe"):
                err_url = f"https://{host}/qshield_404_probe_xyz"
                err_resp, err_cached = await self._fetch_or_cache(
                    client, err_url, ctx,
                )
                if not err_cached and err_resp is not None:
                    reqs += 1
                if err_resp is not None:
                    err_body = err_resp.text[:4000]
                    for pat, cat, tech in ERROR_PAGE_SIGS:
                        if re.search(pat, err_body, re.IGNORECASE):
                            acc.add(
                                host=host,
                                category=cat,
                                name=tech,
                                confidence="medium",
                                evidence=f"error page: {pat[:40]}",
                            )
                            break
        except Exception:
            pass

        # ── Favicon fingerprinting ──
        try:
            async with ctx.throttle.acquire("http_probe"):
                fav_url = f"https://{host}/favicon.ico"
                fav_resp, fav_cached = await self._fetch_or_cache(
                    client, fav_url, ctx,
                )
                if not fav_cached and fav_resp is not None:
                    reqs += 1
                if fav_resp is not None and fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                    fav_hash = hashlib.md5(fav_resp.content).hexdigest()
                    acc.add(
                        host=host,
                        category="favicon",
                        name=f"hash:{fav_hash}",
                        confidence="low",
                        evidence=f"favicon MD5 {fav_hash}",
                    )
        except Exception:
            pass

        return reqs
