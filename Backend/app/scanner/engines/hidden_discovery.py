"""
QuantumShield — Hidden Endpoint Discovery Engine (Stage 9)

Discovers robots.txt paths, sitemap URLs, common hidden paths via
dictionary probing, backup files, admin panels, sensitive files, and
JS-extracted routes.  All confidence-scored.

Hardening changes (v2):
  WEB-04: Bounded streaming reads — avoids full-body OOM on large files
  WEB-05: JS-extracted paths are DiscoveredReferences, not verified live findings
  WEB-03: JS URL fetches are scope-validated before downloading
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.scanner.models import HiddenFinding, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# WEB-04: Response body limits for hidden discovery
_MAX_BODY_BYTES = 256 * 1024   # 256 KB for path-fuzz response bodies
_MAX_JS_BYTES   = 512 * 1024   # 512 KB for JavaScript files
_MAX_CONFIDENCE_BODY = 2000    # chars used for confidence scoring body check

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store",
    "/config.php", "/config.json", "/config.yaml", "/config.yml",
    "/wp-config.php", "/settings.py", "/application.properties",
    "/database.yml", "/secrets.yml", "/web.config",
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/adminer.php", "/console", "/actuator", "/actuator/env",
    "/actuator/health", "/debug", "/_debug", "/server-status",
    "/server-info",
]

BACKUP_EXTENSIONS = [".bak", ".old", "~", ".swp", ".orig", ".zip", ".tar.gz"]


def _load_paths() -> list[str]:
    path = _DATA_DIR / "common_paths.txt"
    if path.is_file():
        return [
            l.strip()
            for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")
        ]
    return SENSITIVE_FILES + ADMIN_PATHS


@dataclass
class _WebTarget:
    host: str
    base_url: str

class HiddenDiscoveryEngine(ScanStage):
    name = "hidden_discovery"
    order = 9
    timeout_seconds = 90
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["hidden_findings"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        findings: list[dict] = []
        request_count = 0
        web_hosts = self._web_hosts(ctx)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=5.0,
        ) as client:
            for target in web_hosts:
                try:
                    hf, reqs = await self._probe_host(client, target, ctx)
                    findings.extend(hf)
                    request_count += reqs
                except Exception:
                    logger.debug("Hidden discovery skipped for %s", target.host, exc_info=True)

        return StageResult(
            status="completed",
            data={"hidden_findings": findings},
            request_count=request_count,
        )

    @staticmethod
    def _web_hosts(ctx: ScanContext) -> list['_WebTarget']:
        from app.scanner.engines.web_discovery import _ScopePolicy
        policy = _ScopePolicy(ctx)
        
        targets: dict[str, _WebTarget] = {}
        web_ports = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 4443, 9443}
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else (
                svc.model_dump() if hasattr(svc, "model_dump") else {}
            )
            proto = s.get("protocol_category", "").lower()
            port = s.get("port")
            try:
                port_int = int(port) if port is not None else 0
            except (TypeError, ValueError):
                port_int = 0
            is_web = proto in ("web", "http", "https") or port_int in web_ports
            if is_web:
                h = s.get("host", "").strip()
                if h:
                    scheme = "https" if port_int in {443, 8443, 4443, 9443} or proto == "https" else "http"
                    if port_int and port_int not in {80, 443, 0}:
                        base_url = f"{scheme}://{h}:{port_int}"
                    else:
                        base_url = f"{scheme}://{h}"

                    allowed, _ = policy.is_url_authorized(base_url)
                    if allowed and base_url not in targets:
                        targets[base_url] = _WebTarget(host=h, base_url=base_url)
        if not targets:
            for sub in ctx.subdomains or []:
                if isinstance(sub, dict):
                    h = sub.get("hostname") or sub.get("host") or sub.get("subdomain") or ""
                elif isinstance(sub, str):
                    h = sub
                else:
                    h = ""
                h = h.strip()
                if h:
                    base_url = f"https://{h}"
                    allowed, _ = policy.is_url_authorized(base_url)
                    if allowed and base_url not in targets:
                        targets[base_url] = _WebTarget(host=h, base_url=base_url)
        return list(targets.values())

    async def _probe_host(self, client: httpx.AsyncClient, target: _WebTarget, ctx: ScanContext):
        findings: list[dict] = []
        reqs = 0
        base = target.base_url
        host = target.host
        consecutive_429 = 0

        is_waf = any(
            (i if isinstance(i, dict) else {}).get("waf_detected")
            for i in (ctx.cdn_waf_intel or [])
            if (i if isinstance(i, dict) else {}).get("host") == host
        )

        robots_paths = await self._parse_robots(client, target, ctx)
        reqs += 1

        sitemap_paths = await self._parse_sitemap(client, target, ctx)
        reqs += 1

        wordlist = _load_paths()
        if is_waf:
            wordlist = SENSITIVE_FILES + ADMIN_PATHS

        extra = ctx.extra_hidden_paths or []
        all_paths = list(dict.fromkeys(
            robots_paths + sitemap_paths + wordlist + extra + SENSITIVE_FILES + ADMIN_PATHS
        ))

        # HIDDEN-01: Custom 404 / SPA Baseline
        import uuid
        baseline_path = f"/notfound_{uuid.uuid4().hex[:8]}"
        is_spa_fallback = False
        custom_404_text = ""
        baseline_status = 404
        try:
            async with ctx.throttle.acquire("path_fuzz"):
                async with client.stream("GET", f"{base}{baseline_path}", timeout=5.0) as b_resp:
                    reqs += 1
                    baseline_status = b_resp.status_code
                    if baseline_status == 200:
                        is_spa_fallback = True
                    b_bytes = b""
                    total = 0
                    async for chunk in b_resp.aiter_bytes(8192):
                        if total + len(chunk) > _MAX_CONFIDENCE_BODY:
                            b_bytes += chunk[:_MAX_CONFIDENCE_BODY - total]
                            break
                        b_bytes += chunk
                        total += len(chunk)
                    custom_404_text = b_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

        for path in all_paths:
            if consecutive_429 > 5:
                logger.info("Stopping hidden probes on %s — too many 429s", host)
                break
            try:
                async with ctx.throttle.acquire("path_fuzz"):
                    # HIDDEN-07: Bounded streaming for large files
                    async with client.stream("GET", f"{base}{path}", timeout=5.0) as resp:
                        reqs += 1

                        if resp.status_code == 429:
                            consecutive_429 += 1
                            continue
                        else:
                            consecutive_429 = 0

                        body_bytes = b""
                        total = 0
                        async for chunk in resp.aiter_bytes(8192):
                            if total + len(chunk) > _MAX_CONFIDENCE_BODY:
                                body_bytes += chunk[:_MAX_CONFIDENCE_BODY - total]
                                break
                            body_bytes += chunk
                            total += len(chunk)
                        
                        body_text = body_bytes.decode("utf-8", errors="replace")

                    confidence = self._confidence(resp.status_code, path, body_text, custom_404_text, is_spa_fallback, baseline_status)
                    if confidence >= 0.3:
                        findings.append(HiddenFinding(
                            host=host,
                            path=path,
                            status_code=resp.status_code,
                            discovery_source=self._source(path, robots_paths, sitemap_paths),
                            finding_type=self._classify(path),
                            risk=self._risk(path, resp.status_code),
                            confidence=confidence,
                            evidence=f"HTTP {resp.status_code} on {path}",
                        ).model_dump())

                        if resp.status_code == 200:
                            for ext in BACKUP_EXTENSIONS:
                                try:
                                    async with ctx.throttle.acquire("path_fuzz"):
                                        async with client.stream("GET", f"{base}{path}{ext}", timeout=5.0) as br:
                                            reqs += 1
                                            if br.status_code == 200:
                                                findings.append(HiddenFinding(
                                                    host=host, path=f"{path}{ext}",
                                                    status_code=200,
                                                    discovery_source="backup_probe",
                                                    finding_type="backup_file",
                                                    risk="high",
                                                    confidence=0.75,
                                                    evidence=f"Backup file found: {path}{ext}",
                                                ).model_dump())
                                except Exception:
                                    pass

            except Exception:
                pass

        # WEB-05: JS routes are DiscoveredReferences, NOT verified live findings.
        # They are logged with finding_type="js_reference" and confidence=0.4
        # (below the confidence threshold used by downstream risk engines for live findings).
        js_routes = await self._extract_js_routes(client, target, ctx)
        reqs += 1
        for route in js_routes:
            findings.append(HiddenFinding(
                host=host,
                path=route,
                status_code=0,                 # Not yet verified — no HTTP request made
                discovery_source="js_extraction",
                finding_type="js_reference",   # WEB-05: was "api_leak"
                risk="info",                   # WEB-05: not a confirmed issue
                confidence=0.4,                # WEB-05: below verified-finding threshold
                evidence=f"Path string extracted from JavaScript source (unverified reference): {route}",
            ).model_dump())

        return findings, reqs

    async def _parse_robots(self, client, target: _WebTarget, ctx) -> list[str]:
        paths: list[str] = []
        try:
            async with ctx.throttle.acquire("http_probe"):
                async with client.stream("GET", f"{target.base_url}/robots.txt", timeout=5.0) as resp:
                    if resp.status_code == 200:
                        body_bytes = b""
                        total = 0
                        async for chunk in resp.aiter_bytes(8192):
                            if total + len(chunk) > _MAX_BODY_BYTES:
                                break
                            body_bytes += chunk
                            total += len(chunk)
                        text = body_bytes.decode("utf-8", errors="replace")
                        for line in text.splitlines():
                            if line.strip().lower().startswith("disallow:"):
                                p = line.split(":", 1)[1].strip()
                                if p and p != "/":
                                    paths.append(p)
                                    if len(paths) >= 50:
                                        break
        except Exception:
            pass
        return paths

    async def _parse_sitemap(self, client, target: _WebTarget, ctx) -> list[str]:
        paths: list[str] = []
        try:
            async with ctx.throttle.acquire("http_probe"):
                async with client.stream("GET", f"{target.base_url}/sitemap.xml", timeout=5.0) as resp:
                    if resp.status_code == 200:
                        body_bytes = b""
                        total = 0
                        async for chunk in resp.aiter_bytes(8192):
                            if total + len(chunk) > _MAX_BODY_BYTES:
                                break
                            body_bytes += chunk
                            total += len(chunk)
                        text = body_bytes.decode("utf-8", errors="replace")
                        locs = re.findall(r"<loc>(.*?)</loc>", text, re.IGNORECASE)
                        from urllib.parse import urlparse
                        for loc in locs:
                            parsed = urlparse(loc)
                            if parsed.path and parsed.path != "/":
                                paths.append(parsed.path)
                                if len(paths) >= 50:
                                    break
        except Exception:
            pass
        return paths

    async def _extract_js_routes(self, client, target: _WebTarget, ctx) -> list[str]:
        """
        Extract API-like path strings from JavaScript files.
        WEB-03: Only fetches JS files whose URL is same-host.
        WEB-04: Reads JS file body up to _MAX_JS_BYTES to avoid OOM.
        WEB-05: Returns raw string matches — caller labels them as js_reference.
        """
        routes: set[str] = set()
        try:
            async with ctx.throttle.acquire("http_probe"):
                async with client.stream("GET", f"{target.base_url}/", follow_redirects=False, timeout=5.0) as resp:
                    html_bytes = b""
                    total = 0
                    async for chunk in resp.aiter_bytes(8192):
                        if total + len(chunk) > 16384:
                            html_bytes += chunk[:16384 - total]
                            break
                        html_bytes += chunk
                        total += len(chunk)
                    html_text = html_bytes.decode("utf-8", errors="replace")

                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html_text)

                for js_url in js_urls:
                    # WEB-03: Normalize and scope-check the JS URL before fetching
                    if js_url.startswith("http"):
                        full = js_url
                        try:
                            parsed = urlparse(js_url)
                            if parsed.hostname and parsed.hostname.lower() != target.host.lower():
                                logger.debug(
                                    "Skipping cross-origin JS: %s (origin: %s)", js_url, target.host
                                )
                                continue
                        except Exception:
                            continue
                        
                        # HIDDEN-04: Extra SSRF protection
                        from app.scanner.engines.web_discovery import _ScopePolicy
                        policy = _ScopePolicy(ctx)
                        allowed, reason = policy.is_url_authorized(full)
                        if not allowed:
                            logger.debug("Skipping JS url %s: %s", full, reason)
                            continue

                    elif js_url.startswith("/"):
                        full = f"{target.base_url}{js_url}"
                    else:
                        full = f"{target.base_url}/{js_url}"

                    try:
                        async with ctx.throttle.acquire("http_probe"):
                            # WEB-04: Stream JS with bounded read
                            async with client.stream("GET", full, timeout=8.0) as stream:
                                body, truncated = b"", False
                                chunks = []
                                total = 0
                                async for chunk in stream.aiter_bytes(8192):
                                    if total + len(chunk) > _MAX_JS_BYTES:
                                        chunks.append(chunk[: _MAX_JS_BYTES - total])
                                        truncated = True
                                        break
                                    chunks.append(chunk)
                                    total += len(chunk)
                                body = b"".join(chunks)
                            js_text = body.decode("utf-8", errors="replace")
                            found = re.findall(
                                r'["\`](/(?:api|v\d+|rest|graphql)[^"\`\s?#]{2,60})["\`]',
                                js_text,
                            )
                            routes.update(found)
                    except Exception:
                        pass
        except Exception:
            pass
        return list(routes)

    @staticmethod
    def _confidence(status: int, path: str, body: str, custom_404_body: str = "", is_spa: bool = False, baseline_status: int = 404) -> float:
        if status == 404:
            return 0.0
            
        if status == baseline_status and status in (301, 302, 403, 401):
            return 0.1
            
        base = {200: 0.7, 403: 0.5, 401: 0.6, 301: 0.4, 302: 0.3}.get(status, 0.1)
        
        if is_spa and status == 200:
            base *= 0.1
            
        if custom_404_body and body and status == 200:
            import difflib
            ratio = difflib.SequenceMatcher(None, custom_404_body, body).quick_ratio()
            if ratio > 0.8:
                return base * 0.1

        if ".git/HEAD" in path and "ref: refs/heads/" in body:
            return 1.0
        if ".env" in path and any(k in body for k in ("DB_", "SECRET", "API_KEY", "PASSWORD")):
            return 1.0
        if "swagger" in path.lower() and '"openapi"' in body.lower():
            return 0.95
        if "actuator" in path and '"status"' in body:
            return 0.85
        if any(p in body.lower()[:500] for p in ("page not found", "404 error", "not found")):
            return base * 0.2
        return base

    @staticmethod
    def _classify(path: str) -> str:
        pl = path.lower()
        if ".git" in pl or ".svn" in pl:
            return "git_exposure"
        if ".env" in pl or "config" in pl or "secret" in pl or "database" in pl:
            return "config_exposure"
        if any(a in pl for a in ("admin", "manage", "console", "panel", "phpmyadmin")):
            return "admin_panel"
        if any(a in pl for a in (".bak", ".old", ".zip", ".swp", "backup")):
            return "backup_file"
        if any(a in pl for a in ("swagger", "openapi", "api-doc", "graphql")):
            return "api_leak"
        return "info_disclosure"

    @staticmethod
    def _risk(path: str, status: int) -> str:
        pl = path.lower()
        if ".git" in pl or ".env" in pl or "secret" in pl:
            return "critical"
        if "admin" in pl or "config" in pl or "backup" in pl:
            return "high"
        if status in (401, 403):
            return "medium"
        return "medium"

    @staticmethod
    def _source(path, robots, sitemap) -> str:
        if path in robots:
            return "robots_txt"
        if path in sitemap:
            return "sitemap"
        if path in SENSITIVE_FILES:
            return "sensitive_file"
        if path in ADMIN_PATHS:
            return "admin"
        return "brute_force"
