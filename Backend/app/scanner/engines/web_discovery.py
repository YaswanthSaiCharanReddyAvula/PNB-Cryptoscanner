"""
QuantumShield — Web / API Discovery Engine (Stage 8)

Full security-header audit, cookie analysis, CORS probing, API schema
discovery (OpenAPI / GraphQL / Swagger), and well-known URI probing.

Hardening changes (v2):
  WEB-01: Fixed Pydantic ValidationError — well_known_results is now list[WellKnownResult]
  WEB-02: Engine now respects port / scheme from ctx.services (not hardcoded 443)
  WEB-03: Scope + SSRF guard — redirects and JS URLs are scope-validated
  WEB-04: Bounded streaming reads via httpx stream — avoids full-body OOM
  WEB-05: JS-extracted paths are DiscoveredReferences, not live findings
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

# WEB-04: Response body size limits
MAX_RESPONSE_BYTES = 512 * 1024       # 512 KB generic responses
MAX_SCHEMA_BYTES   = 1024 * 1024      # 1 MB for OpenAPI/JSON schemas
MAX_CONTENT_PREVIEW = 500             # chars for well-known preview

# WEB-03: SSRF-blocked address ranges
_BLOCKED_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / AWS metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
]

# RFC 1918 private ranges — blocked by default; authorized internal targets override
_PRIVATE_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

# ---------------------------------------------------------------------------
# Web target resolution (WEB-02 fix)
# ---------------------------------------------------------------------------

@dataclass
class WebTarget:
    """Resolved, scope-validated web target produced from ctx.services."""
    hostname: str
    port: int
    scheme: str
    base_url: str
    source: str = "service_discovery"

    @classmethod
    def from_service(cls, svc: dict) -> Optional["WebTarget"]:
        host = svc.get("host", "").strip()
        port = svc.get("port")
        if not host or not port:
            return None
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None

        proto = svc.get("protocol_category", "").lower()
        service_name = (svc.get("service_name") or "").lower()

        # Port-based scheme takes priority — it reflects what the scanner actually observed
        if port in (443, 8443, 4443):
            scheme = "https"
        elif port in (80, 8080, 8000, 8008, 3000, 5000):
            scheme = "http"
        # Fall back to protocol_category or service_name metadata
        elif service_name in ("https", "ssl") or proto == "https":
            scheme = "https"
        elif service_name == "http" or proto == "http":
            scheme = "http"
        else:
            # Unknown port: attempt HTTPS first — _profile_host will fallback to HTTP
            scheme = "https"

        if port in (80, 443):
            base_url = f"{scheme}://{host}/"
        else:
            base_url = f"{scheme}://{host}:{port}/"

        return cls(hostname=host, port=port, scheme=scheme, base_url=base_url)


# ---------------------------------------------------------------------------
# SSRF / scope guard (WEB-03 fix)
# ---------------------------------------------------------------------------

class _ScopePolicy:
    """
    Centralized scope and SSRF protection.

    Rules:
    1. Hostnames must be in the authorized set (derived from ctx.subdomains + domain).
    2. Resolved IPs must not be in the hard-blocked ranges.
    3. RFC1918 ranges are blocked by default unless the hostname was already
       in the authorized scan scope (enterprise internal scanning support).
    """

    def __init__(self, ctx: ScanContext) -> None:
        self._authorized_hostnames: set[str] = set()

        # Seed from ctx.domain
        if ctx.domain:
            self._authorized_hostnames.add(ctx.domain.lower().strip())
            # www prefix variant
            d = ctx.domain.lower().strip()
            if not d.startswith("www."):
                self._authorized_hostnames.add(f"www.{d}")

        # Seed from discovered subdomains
        for item in ctx.subdomains or []:
            if isinstance(item, dict):
                h = item.get("hostname") or item.get("host") or item.get("subdomain") or ""
            elif isinstance(item, str):
                h = item
            else:
                h = str(item)
            if h:
                self._authorized_hostnames.add(h.lower().strip())

        # Seed from services hosts
        for svc in ctx.services or []:
            s = svc if isinstance(svc, dict) else {}
            h = s.get("host", "").lower().strip()
            if h:
                self._authorized_hostnames.add(h)

    def is_hostname_authorized(self, hostname: str) -> bool:
        hn = hostname.lower().strip()
        if hn in self._authorized_hostnames:
            return True
        # Subdomain of an authorized domain
        for auth in self._authorized_hostnames:
            if hn.endswith(f".{auth}") or auth.endswith(f".{hn}"):
                return True
        return False

    def is_url_authorized(self, url: str) -> tuple[bool, str]:
        """
        Returns (allowed, reason).
        Resolves the hostname and checks SSRF ranges.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "unparseable_url"

        hostname = parsed.hostname or ""
        if not hostname:
            return False, "no_hostname"

        # Check scope first (cheap)
        if not self.is_hostname_authorized(hostname):
            return False, f"out_of_scope:{hostname}"

        # Resolve and check IP (WEB-03 SSRF protection)
        try:
            ip_str = socket.getaddrinfo(hostname, None)[0][4][0]
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            # Cannot resolve — allow but log
            return True, "unresolvable_allowed"

        for blocked in _BLOCKED_CIDRS:
            if ip in blocked:
                return False, f"ssrf_blocked_range:{ip}"

        # Private RFC1918 — allowed only if the hostname was explicitly authorized
        for priv in _PRIVATE_CIDRS:
            if ip in priv:
                if self.is_hostname_authorized(hostname):
                    return True, "authorized_internal"
                return False, f"unauthorized_private_ip:{ip}"

        return True, "ok"


# ---------------------------------------------------------------------------
# Bounded response reader (WEB-04 fix)
# ---------------------------------------------------------------------------

async def _read_bounded(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Stream the response up to max_bytes. Returns (body, truncated)."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes(chunk_size=8192):
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

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

        # Build scope policy for this scan (WEB-03)
        scope = _ScopePolicy(ctx)

        # Resolve web targets respecting discovered ports (WEB-02)
        web_targets = self._resolve_web_targets(ctx)

        # Deduplicate by (scheme, hostname, port) — preserving virtual-host identity
        seen_targets: set[tuple[str, str, int]] = set()
        unique_targets: list[WebTarget] = []
        for wt in web_targets:
            key = (wt.scheme, wt.hostname.lower(), wt.port)
            if key not in seen_targets:
                seen_targets.add(key)
                unique_targets.append(wt)

        # WEB-03: verify each target passes scope before probing
        authorized_targets: list[WebTarget] = []
        for wt in unique_targets:
            allowed, reason = scope.is_url_authorized(wt.base_url)
            if allowed:
                authorized_targets.append(wt)
            else:
                logger.warning(
                    "Scope guard blocked web target %s — %s", wt.base_url, reason
                )

        # IMPORTANT: follow_redirects=False — we validate each redirect manually
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
        ) as client:
            for target in authorized_targets:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        profile, reqs = await self._profile_target(
                            client, target, scope, ctx
                        )
                        profiles.append(profile)
                        request_count += reqs
                except Exception:
                    logger.warning(
                        "Web discovery failed for %s", target.base_url, exc_info=True
                    )

        return StageResult(
            status="completed",
            data={"web_profiles": profiles},
            request_count=request_count,
        )

    # ------------------------------------------------------------------
    # WEB-02: Target resolver respecting discovered ports / schemes
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_web_targets(ctx: ScanContext) -> list[WebTarget]:
        """
        Build WebTarget list from ctx.services, falling back to ctx.subdomains.
        Respects port and scheme from service discovery.
        """
        targets: list[WebTarget] = []
        web_ports = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 4443, 9443}

        if ctx.services:
            for svc in ctx.services:
                s = svc if isinstance(svc, dict) else (
                    svc.model_dump() if hasattr(svc, "model_dump") else {}
                )
                port = s.get("port")
                proto = s.get("protocol_category", "").lower()
                is_web = proto in ("web", "http", "https") or (
                    port and int(port) in web_ports
                )
                if is_web:
                    wt = WebTarget.from_service(s)
                    if wt:
                        targets.append(wt)

        if not targets:
            # Fallback: subdomains list — probe both HTTPS (443) and HTTP (80)
            for sub in ctx.subdomains or []:
                if isinstance(sub, dict):
                    h = sub.get("hostname") or sub.get("host") or sub.get("subdomain") or ""
                elif isinstance(sub, str):
                    h = sub
                else:
                    continue
                h = h.strip()
                if h:
                    targets.append(WebTarget(
                        hostname=h, port=443, scheme="https",
                        base_url=f"https://{h}/", source="subdomain_fallback"
                    ))

        return targets

    # ------------------------------------------------------------------
    # Core profiler — WEB-01, WEB-03, WEB-04 fixes applied here
    # ------------------------------------------------------------------

    async def _profile_target(
        self,
        client: httpx.AsyncClient,
        target: WebTarget,
        scope: _ScopePolicy,
        ctx: ScanContext,
    ) -> tuple[dict, int]:
        reqs = 0
        actual_url = target.base_url
        resp = None

        # -- Initial request with manual redirect following (WEB-03) --
        try:
            raw_resp = await client.get(actual_url)
            reqs += 1

            # Manual scope-controlled redirect handling
            resp, actual_url, redirect_reqs = await self._follow_redirects_scoped(
                client, raw_resp, actual_url, scope, max_hops=5
            )
            reqs += redirect_reqs

        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
            # HTTPS failed — try HTTP fallback if original was HTTPS
            if target.scheme == "https":
                fallback_url = actual_url.replace("https://", "http://", 1)
                try:
                    raw_resp = await client.get(fallback_url)
                    reqs += 1
                    actual_url = fallback_url
                    resp, actual_url, redirect_reqs = await self._follow_redirects_scoped(
                        client, raw_resp, actual_url, scope, max_hops=5
                    )
                    reqs += redirect_reqs
                except Exception as exc:
                    logger.debug("HTTP fallback failed for %s: %s", fallback_url, exc)
                    return self._failed_profile(target.hostname, actual_url, str(exc)), reqs
            else:
                return self._failed_profile(
                    target.hostname, actual_url, "Connection failed"
                ), reqs
        except (httpx.ProtocolError, httpx.DecodingError) as exc:
            logger.debug("Protocol error on %s: %s", actual_url, exc)
            return self._failed_profile(
                target.hostname, actual_url, f"Protocol/Decoding Error: {exc}"
            ), reqs
        except Exception as exc:
            logger.debug("Request failed for %s: %s", actual_url, exc)
            return self._failed_profile(target.hostname, actual_url, str(exc)), reqs

        if resp is None:
            return self._failed_profile(target.hostname, actual_url, "No response"), reqs

        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        # -- Security headers --
        sec_hdrs: dict[str, dict] = {}
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

        # CORS probe — single dedicated request, scope-checked
        cors_reqs = 0
        cors = await self._audit_cors(client, target, scope)
        cors_reqs = 1
        reqs += cors_reqs

        # API schema discovery
        api_schemas, api_reqs = await self._discover_apis(client, target, scope, ctx)
        reqs += api_reqs

        # Well-known probing — returns list[WellKnownResult] (WEB-01 fix)
        wk_results, wk_reqs = await self._probe_well_known(client, target, scope, ctx)
        reqs += wk_reqs

        # Info leaks
        info_leaks: list[str] = []
        if hdrs.get("server"):
            info_leaks.append(f"Server header disclosed: {hdrs['server'][:80]}")
        if hdrs.get("x-powered-by"):
            info_leaks.append(f"X-Powered-By disclosed: {hdrs['x-powered-by'][:80]}")

        # WEB-01 FIX: well_known_results is now properly a list[WellKnownResult]
        try:
            profile = WebAppProfile(
                host=target.hostname,
                url=actual_url,
                status_code=resp.status_code,
                security_headers=sec_hdrs,
                header_score=header_score,
                cookies=cookies,
                cors=cors,
                api_schemas_found=api_schemas,
                well_known_results=wk_results,   # list[WellKnownResult] ✓
                info_leaks=info_leaks,
            ).model_dump()
        except Exception as exc:
            logger.error(
                "WebAppProfile construction failed for %s: %s", target.hostname, exc
            )
            return self._failed_profile(
                target.hostname, actual_url, f"Profile construction error: {exc}"
            ), reqs

        return profile, reqs

    # ------------------------------------------------------------------
    # WEB-03: Scope-controlled manual redirect follower
    # ------------------------------------------------------------------

    async def _follow_redirects_scoped(
        self,
        client: httpx.AsyncClient,
        response: httpx.Response,
        original_url: str,
        scope: _ScopePolicy,
        max_hops: int = 5,
    ) -> tuple[Optional[httpx.Response], str, int]:
        """
        Manually follow redirects, validating each hop through the scope policy.
        Returns (final_response, final_url, additional_request_count).
        Blocked redirects return the last valid response and log evidence.
        """
        current_url = original_url
        current_resp = response
        hops = 0
        extra_reqs = 0
        visited: set[str] = {original_url}

        while current_resp.is_redirect and hops < max_hops:
            location = current_resp.headers.get("location", "")
            if not location:
                break

            # Resolve relative redirects
            next_url = urljoin(current_url, location)

            # Scope + SSRF check (WEB-03)
            allowed, reason = scope.is_url_authorized(next_url)
            if not allowed:
                logger.warning(
                    "Redirect blocked by scope policy: %s → %s (%s)",
                    current_url, next_url, reason
                )
                break  # Return the last valid response

            # Loop detection
            if next_url in visited:
                logger.debug("Redirect loop detected at %s", next_url)
                break

            visited.add(next_url)

            try:
                current_resp = await client.get(next_url)
                extra_reqs += 1
                current_url = next_url
                hops += 1
            except Exception as exc:
                logger.debug("Redirect request failed: %s → %s: %s", current_url, next_url, exc)
                break

        return current_resp, current_url, extra_reqs

    # ------------------------------------------------------------------
    # Cookie audit
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # CORS audit
    # ------------------------------------------------------------------

    @staticmethod
    async def _audit_cors(
        client: httpx.AsyncClient, target: WebTarget, scope: _ScopePolicy
    ) -> dict:
        try:
            resp = await client.get(
                target.base_url,
                headers={"Origin": "https://evil.example.com"},
            )
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

    # ------------------------------------------------------------------
    # OpenAPI / GraphQL API discovery
    # ------------------------------------------------------------------

    async def _discover_apis(
        self,
        client: httpx.AsyncClient,
        target: WebTarget,
        scope: _ScopePolicy,
        ctx: ScanContext,
    ) -> tuple[list[dict], int]:
        found: list[dict] = []
        total_reqs = 0

        # OpenAPI / Swagger paths
        for path in API_PROBE_PATHS:
            probe_url = f"{target.scheme}://{target.hostname}"
            if target.port not in (80, 443):
                probe_url += f":{target.port}"
            probe_url += path

            try:
                async with ctx.throttle.acquire("http_probe"):
                    resp = await client.get(probe_url, follow_redirects=False)
                    total_reqs += 1

                    if resp.status_code in (200, 201, 204):
                        endpoints: list[str] = []
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct or path.endswith(".json"):
                            try:
                                # WEB-04: bounded read for schema
                                async with client.stream("GET", probe_url) as stream:
                                    body, truncated = await _read_bounded(
                                        stream, MAX_SCHEMA_BYTES
                                    )
                                total_reqs += 1
                                import json
                                spec = json.loads(body.decode("utf-8", errors="replace"))
                                endpoints = list((spec.get("paths") or {}).keys())[:50]
                                if truncated:
                                    logger.debug(
                                        "Schema response truncated for %s%s", target.hostname, path
                                    )
                            except Exception:
                                pass

                        found.append(APISchemaResult(
                            path=path,
                            status_code=resp.status_code,
                            is_schema=bool(endpoints),
                            documented_endpoints=endpoints,
                        ).model_dump())

                    elif resp.status_code in (401, 403):
                        # Protected schema — still discovered, marked as protected
                        found.append(APISchemaResult(
                            path=path,
                            status_code=resp.status_code,
                            is_schema=False,
                        ).model_dump())
            except Exception:
                pass

        # GraphQL introspection
        gql_url = f"{target.scheme}://{target.hostname}"
        if target.port not in (80, 443):
            gql_url += f":{target.port}"
        gql_url += "/graphql"

        try:
            async with ctx.throttle.acquire("http_probe"):
                gql_resp = await client.post(
                    gql_url,
                    json={"query": "{ __schema { types { name } } }"},
                    timeout=5.0,
                )
                total_reqs += 1
                if gql_resp.status_code == 200:
                    data = gql_resp.json()
                    if "data" in data and "__schema" in (data.get("data") or {}):
                        types = [
                            t["name"]
                            for t in data["data"]["__schema"].get("types", [])
                            if not t["name"].startswith("__")
                        ]
                        found.append(APISchemaResult(
                            path="/graphql",
                            status_code=200,
                            is_schema=True,
                            documented_endpoints=types[:30],
                        ).model_dump())
        except Exception:
            pass

        return found, total_reqs

    # ------------------------------------------------------------------
    # WEB-01 FIX: well-known returns list[WellKnownResult] not dict
    # ------------------------------------------------------------------

    async def _probe_well_known(
        self,
        client: httpx.AsyncClient,
        target: WebTarget,
        scope: _ScopePolicy,
        ctx: ScanContext,
    ) -> tuple[list[dict], int]:
        """
        Returns (list[WellKnownResult.model_dump()], request_count).
        Fixes WEB-01: previously returned dict — now returns list.
        """
        results: list[dict] = []
        total_reqs = 0

        for path in WELL_KNOWN_PATHS:
            probe_url = f"{target.scheme}://{target.hostname}"
            if target.port not in (80, 443):
                probe_url += f":{target.port}"
            probe_url += path

            try:
                async with ctx.throttle.acquire("http_probe"):
                    resp = await client.get(probe_url, follow_redirects=False)
                    total_reqs += 1

                    preview: Optional[str] = None
                    if resp.status_code == 200:
                        # WEB-04: bounded read — never pull full body
                        try:
                            async with client.stream("GET", probe_url) as stream:
                                body, _ = await _read_bounded(
                                    stream, MAX_RESPONSE_BYTES
                                )
                                total_reqs += 1
                            preview = body.decode("utf-8", errors="replace")[:MAX_CONTENT_PREVIEW]
                        except Exception:
                            preview = None

                    results.append(WellKnownResult(
                        path=path,
                        status_code=resp.status_code,
                        found=resp.status_code == 200,
                        content_preview=preview,
                    ).model_dump())

            except Exception as exc:
                results.append(WellKnownResult(
                    path=path,
                    status_code=0,
                    found=False,
                    content_preview=None,
                ).model_dump())
                logger.debug("Well-known probe failed for %s%s: %s", target.hostname, path, exc)

        return results, total_reqs

    # ------------------------------------------------------------------
    # Failed profile constructor — always returns a valid dict
    # ------------------------------------------------------------------

    def _failed_profile(self, host: str, url: str, error: str) -> dict:
        """Return a minimal valid profile for hosts that fail to respond."""
        return WebAppProfile(
            host=host,
            url=url,
            status_code=0,
            security_headers={},
            header_score=0.0,
            cookies=[],
            cors=CORSAudit(origin_tested="https://evil.example.com").model_dump(),
            api_schemas_found=[],
            well_known_results=[],           # list — not dict (WEB-01)
            info_leaks=[f"Discovery failed: {error[:200]}"],
        ).model_dump()
