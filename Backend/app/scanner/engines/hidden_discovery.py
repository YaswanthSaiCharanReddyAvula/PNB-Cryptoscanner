"""
QuantumShield — Hidden Endpoint Discovery Engine (Stage 9)

Discovers robots.txt paths, sitemap URLs, common hidden paths via
dictionary probing, backup files, admin panels, sensitive files, and
JS-extracted routes.  All confidence-scored.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

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
            for host in web_hosts:
                try:
                    hf, reqs = await self._probe_host(client, host, ctx)
                    findings.extend(hf)
                    request_count += reqs
                except Exception:
                    logger.debug("Hidden discovery skipped for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"hidden_findings": findings},
            request_count=request_count,
        )

    @staticmethod
    def _web_hosts(ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            if s.get("protocol_category") == "web" or s.get("port") in (80, 443, 8080, 8443):
                h = s.get("host", "")
                if h and h not in hosts:
                    hosts.append(h)
        if not hosts:
            hosts = list(ctx.subdomains or [])
        return hosts

    async def _probe_host(self, client: httpx.AsyncClient, host: str, ctx: ScanContext):
        findings: list[dict] = []
        reqs = 0
        base = f"https://{host}"
        consecutive_429 = 0

        is_waf = any(
            (i if isinstance(i, dict) else {}).get("waf_detected")
            for i in (ctx.cdn_waf_intel or [])
            if (i if isinstance(i, dict) else {}).get("host") == host
        )

        robots_paths = await self._parse_robots(client, host, ctx)
        reqs += 1

        sitemap_paths = await self._parse_sitemap(client, host, ctx)
        reqs += 1

        wordlist = _load_paths()
        if is_waf:
            wordlist = SENSITIVE_FILES + ADMIN_PATHS

        extra = ctx.extra_hidden_paths or []
        all_paths = list(dict.fromkeys(
            robots_paths + sitemap_paths + wordlist + extra + SENSITIVE_FILES + ADMIN_PATHS
        ))

        for path in all_paths:
            if consecutive_429 > 5:
                logger.info("Stopping hidden probes on %s — too many 429s", host)
                break
            try:
                async with ctx.throttle.acquire("path_fuzz"):
                    resp = await client.get(f"{base}{path}")
                    reqs += 1

                    if resp.status_code == 429:
                        consecutive_429 += 1
                        continue
                    else:
                        consecutive_429 = 0

                    confidence = self._confidence(resp.status_code, path, resp.text[:2000])
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
                                        br = await client.get(f"{base}{path}{ext}")
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

        js_routes = await self._extract_js_routes(client, host, ctx)
        reqs += 1
        for route in js_routes:
            findings.append(HiddenFinding(
                host=host, path=route, status_code=0,
                discovery_source="js_extraction",
                finding_type="api_leak",
                risk="medium",
                confidence=0.5,
                evidence=f"Route found in JavaScript: {route}",
            ).model_dump())

        return findings, reqs

    async def _parse_robots(self, client, host, ctx) -> list[str]:
        paths: list[str] = []
        try:
            async with ctx.throttle.acquire("http_probe"):
                resp = await client.get(f"https://{host}/robots.txt")
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if line.strip().lower().startswith("disallow:"):
                            p = line.split(":", 1)[1].strip()
                            if p and p != "/":
                                paths.append(p)
        except Exception:
            pass
        return paths

    async def _parse_sitemap(self, client, host, ctx) -> list[str]:
        paths: list[str] = []
        try:
            async with ctx.throttle.acquire("http_probe"):
                resp = await client.get(f"https://{host}/sitemap.xml")
                if resp.status_code == 200:
                    locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                    from urllib.parse import urlparse
                    for loc in locs:
                        parsed = urlparse(loc)
                        if parsed.path and parsed.path != "/":
                            paths.append(parsed.path)
        except Exception:
            pass
        return paths

    async def _extract_js_routes(self, client, host, ctx) -> list[str]:
        routes: set[str] = set()
        try:
            async with ctx.throttle.acquire("http_probe"):
                resp = await client.get(f"https://{host}/", follow_redirects=True)
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
                for js_url in js_urls:
                    full = js_url if js_url.startswith("http") else f"https://{host}{js_url}" if js_url.startswith("/") else f"https://{host}/{js_url}"
                    try:
                        async with ctx.throttle.acquire("http_probe"):
                            jr = await client.get(full, timeout=8.0)
                            found = re.findall(r'["\`](/(?:api|v\d+|rest|graphql)[^"\`\s?#]{2,60})["\`]', jr.text)
                            routes.update(found)
                    except Exception:
                        pass
        except Exception:
            pass
        return list(routes)

    @staticmethod
    def _confidence(status: int, path: str, body: str) -> float:
        if status == 404:
            return 0.0
        base = {200: 0.7, 403: 0.5, 401: 0.6, 301: 0.4, 302: 0.3}.get(status, 0.1)
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
