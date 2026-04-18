"""
QuantumShield — Web / API Discovery Engine (Stage 8)

Full security-header audit, cookie analysis, CORS probing, API schema
discovery (OpenAPI / GraphQL), and well-known URI probing.  Replaces
the single-HEAD headers_scanner.py with depth.
"""

from __future__ import annotations

import json
import re
from typing import Optional

import httpx

from app.scanner.models import (
    APISchemaResult,
    CookieAudit,
    CORSAudit,
    HeaderAuditResult,
    StageResult,
    WebAppProfile,
    WellKnownResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

API_PROBE_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api/docs", "/.well-known/openapi",
    "/v1/openapi.json", "/v2/swagger.json",
]

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/.well-known/openid-configuration",
]


class WebAPIDiscoveryEngine(ScanStage):
    name = "web_discovery"
    order = 8
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.IMPORTANT
    required_fields = ["subdomains"]
    writes_fields = ["web_profiles"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        profiles: list[dict] = []
        request_count = 0
        web_hosts = self._web_hosts(ctx)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10.0
        ) as client:
            for host in web_hosts:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        profile, reqs = await self._profile_host(client, host, ctx)
                        profiles.append(profile)
                        request_count += reqs
                except Exception:
                    logger.warning("Web discovery failed for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"web_profiles": profiles},
            request_count=request_count,
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

    async def _profile_host(self, client: httpx.AsyncClient, host: str, ctx: ScanContext):
        reqs = 0
        url = f"https://{host}/"
        try:
            resp = await client.get(url)
            reqs += 1
        except httpx.ConnectError:
            url = f"http://{host}/"
            resp = await client.get(url)
            reqs += 1

        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        sec_hdrs = {}
        present_count = 0
        for h in SECURITY_HEADERS:
            val = hdrs.get(h)
            present = val is not None
            if present:
                present_count += 1
            sec_hdrs[h] = HeaderAuditResult(
                present=present,
                value=val,
                compliant=present,
                issue=None if present else f"Missing {h}",
            ).model_dump()

        header_score = round(present_count / len(SECURITY_HEADERS) * 100, 1)

        cookies = self._audit_cookies(resp)
        cors = await self._audit_cors(client, host, url)
        reqs += 1
        api_schemas = await self._discover_apis(client, host, ctx)
        reqs += len(API_PROBE_PATHS)
        well_known = await self._probe_well_known(client, host, ctx)
        reqs += len(WELL_KNOWN_PATHS)

        info_leaks: list[str] = []
        if hdrs.get("server"):
            info_leaks.append(f"Server header disclosed: {hdrs['server'][:80]}")
        if hdrs.get("x-powered-by"):
            info_leaks.append(f"X-Powered-By disclosed: {hdrs['x-powered-by'][:80]}")

        return WebAppProfile(
            host=host,
            url=url,
            status_code=resp.status_code,
            security_headers=sec_hdrs,
            header_score=header_score,
            cookies=cookies,
            cors=cors,
            api_schemas_found=api_schemas,
            well_known_results=well_known,
            info_leaks=info_leaks,
        ).model_dump(), reqs

    @staticmethod
    def _audit_cookies(resp: httpx.Response) -> list[dict]:
        results: list[dict] = []
        for header_val in resp.headers.get_list("set-cookie"):
            parts = [p.strip() for p in header_val.split(";")]
            if not parts:
                continue
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            flags = {p.lower().split("=")[0].strip() for p in parts[1:]}
            issues: list[str] = []
            secure = "secure" in flags
            http_only = "httponly" in flags
            same_site = None
            for p in parts[1:]:
                if p.strip().lower().startswith("samesite"):
                    same_site = p.split("=", 1)[-1].strip() if "=" in p else None
            if not secure:
                issues.append("Missing Secure flag")
            if not http_only:
                issues.append("Missing HttpOnly flag")
            if not same_site:
                issues.append("Missing SameSite attribute")
            results.append(CookieAudit(
                name=name, secure=secure, http_only=http_only,
                same_site=same_site, issues=issues,
            ).model_dump())
        return results

    @staticmethod
    async def _audit_cors(client: httpx.AsyncClient, host: str, url: str) -> dict:
        try:
            resp = await client.get(url, headers={"Origin": "https://evil.example.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
            permissive = acao == "*" or "evil.example.com" in acao
            risk = "high" if permissive and creds else "medium" if permissive else "low"
            return CORSAudit(
                origin_tested="https://evil.example.com",
                acao=acao or None,
                credentials_allowed=creds,
                is_permissive=permissive,
                risk=risk,
            ).model_dump()
        except Exception:
            return CORSAudit(origin_tested="https://evil.example.com").model_dump()

    async def _discover_apis(self, client: httpx.AsyncClient, host: str, ctx: ScanContext) -> list[dict]:
        found: list[dict] = []
        for path in API_PROBE_PATHS:
            try:
                async with ctx.throttle.acquire("http_probe"):
                    url = f"https://{host}{path}"
                    resp = await client.get(url, follow_redirects=False)
                    if resp.status_code in (200, 201, 204):
                        endpoints: list[str] = []
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct or path.endswith(".json"):
                            try:
                                spec = resp.json()
                                endpoints = list((spec.get("paths") or {}).keys())
                            except Exception:
                                pass
                        found.append(APISchemaResult(
                            path=path, status_code=resp.status_code,
                            is_schema=bool(endpoints),
                            documented_endpoints=endpoints[:50],
                        ).model_dump())
                    elif resp.status_code in (401, 403):
                        found.append(APISchemaResult(
                            path=path, status_code=resp.status_code,
                            is_schema=False,
                        ).model_dump())
            except Exception:
                pass

        try:
            async with ctx.throttle.acquire("http_probe"):
                gql_resp = await client.post(
                    f"https://{host}/graphql",
                    json={"query": "{ __schema { types { name } } }"},
                    timeout=5.0,
                )
                if gql_resp.status_code == 200:
                    data = gql_resp.json()
                    if "data" in data and "__schema" in (data.get("data") or {}):
                        types = [t["name"] for t in data["data"]["__schema"].get("types", []) if not t["name"].startswith("__")]
                        found.append(APISchemaResult(
                            path="/graphql", status_code=200,
                            is_schema=True,
                            documented_endpoints=types[:30],
                        ).model_dump())
        except Exception:
            pass

        return found

    async def _probe_well_known(self, client: httpx.AsyncClient, host: str, ctx: ScanContext) -> dict:
        results: dict[str, dict] = {}
        for path in WELL_KNOWN_PATHS:
            try:
                async with ctx.throttle.acquire("http_probe"):
                    resp = await client.get(f"https://{host}{path}", follow_redirects=False)
                    results[path] = WellKnownResult(
                        path=path,
                        status_code=resp.status_code,
                        found=resp.status_code == 200,
                        content_preview=resp.text[:500] if resp.status_code == 200 else None,
                    ).model_dump()
            except Exception:
                results[path] = WellKnownResult(path=path, status_code=0, found=False).model_dump()
        return results
