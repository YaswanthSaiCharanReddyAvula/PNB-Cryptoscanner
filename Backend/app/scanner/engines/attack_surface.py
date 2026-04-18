"""
QuantumShield — Attack Surface Engine (Stage 14)

Stateful crawler, parameter fuzzer, GraphQL deep tester, and exploit
chain detector.  Runs only in aggressive mode.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.scanner.models import (
    CrawlResult,
    ExploitChain,
    FormData,
    FuzzFinding,
    GraphQLFinding,
    ParamData,
    StageResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

FUZZ_PAYLOADS = {
    "xss_probe":      "<qshield>",
    "sqli_probe":     "' OR '1'='1",
    "ssti_probe":     "{{7*7}}",
    "path_traverse":  "../../etc/passwd",
    "open_redirect":  "https://evil.example.com",
}

CHAIN_PATTERNS: list[dict] = [
    {
        "id": "CHAIN-001",
        "name": "Exposed Admin + No WAF",
        "severity": "critical",
        "conditions": {"hidden_type": "admin_panel", "waf": False},
        "narrative": "Admin panel at {path} is unprotected by a WAF.",
        "remediation": "Restrict admin access to VPN/internal network and deploy a WAF.",
    },
    {
        "id": "CHAIN-002",
        "name": "HNDL + Sensitive API",
        "severity": "critical",
        "conditions": {"hndl": True, "has_api": True},
        "narrative": "Host {host} exposes APIs over quantum-vulnerable key exchange — HNDL risk.",
        "remediation": "Deploy X25519Kyber768 hybrid key exchange on API endpoints.",
    },
    {
        "id": "CHAIN-003",
        "name": "Git Exposure + Config Leak",
        "severity": "critical",
        "conditions": {"hidden_type": "git_exposure"},
        "narrative": ".git directory exposed at {path} — source code and secrets recoverable.",
        "remediation": "Block .git access and rotate any credentials found in commit history.",
    },
    {
        "id": "CHAIN-005",
        "name": "XSS + Stealable Session Cookie",
        "severity": "critical",
        "conditions": {"fuzz_xss": True, "cookie_no_httponly": True},
        "narrative": "Reflected XSS on {url} combined with session cookie missing HttpOnly allows session theft.",
        "remediation": "Sanitise user input and set HttpOnly on all session cookies.",
    },
]


class AttackSurfaceEngine(ScanStage):
    name = "attack_surface"
    order = 14
    timeout_seconds = 180
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["all_findings"]
    merge_strategy = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        findings: list[dict] = []
        request_count = 0
        web_hosts = self._web_hosts(ctx)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10.0,
        ) as client:
            for host in web_hosts[:10]:
                url = f"https://{host}"
                try:
                    crawl, reqs = await self._crawl_host(client, host, url, ctx)
                    request_count += reqs

                    fuzz_results, fuzz_reqs = await self._fuzz(client, crawl, host, ctx)
                    findings.extend(fuzz_results)
                    request_count += fuzz_reqs

                except Exception:
                    logger.debug("Attack surface skipped for %s", host, exc_info=True)

            gql_findings, gql_reqs = await self._test_graphql(client, ctx)
            findings.extend(gql_findings)
            request_count += gql_reqs

        chains = self._detect_chains(ctx, findings)
        findings.extend(chains)

        return StageResult(
            status="completed",
            data={"all_findings": findings},
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
        return hosts or list((ctx.subdomains or [])[:5])

    # ------------------------------------------------------------------
    # Stateful crawler
    # ------------------------------------------------------------------

    async def _crawl_host(self, client, host, base_url, ctx):
        visited: set[str] = set()
        forms: list[dict] = []
        params: list[dict] = []
        queue: list[tuple[str, int]] = [(base_url, 0)]
        reqs = 0

        while queue and len(visited) < 50:
            url, depth = queue.pop(0)
            if url in visited or depth > 3:
                continue
            visited.add(url)

            try:
                async with ctx.throttle.acquire("crawl"):
                    resp = await client.get(url, timeout=8.0)
                    reqs += 1
                    html = resp.text[:65536]

                links = re.findall(r'(?:href|src|action)=["\']([^"\'#]+)', html)
                for link in links:
                    resolved = self._resolve_link(link, url, host)
                    if resolved and resolved not in visited:
                        queue.append((resolved, depth + 1))

                form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
                for block in form_blocks:
                    action = re.search(r'action=["\']([^"\']*)', block)
                    method = re.search(r'method=["\']([^"\']*)', block, re.IGNORECASE)
                    inputs = re.findall(
                        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*))?',
                        block, re.IGNORECASE,
                    )
                    forms.append(FormData(
                        page_url=url,
                        action=action.group(1) if action else url,
                        method=(method.group(1) if method else "GET").upper(),
                        fields=[{"name": n, "type": t or "text"} for n, t in inputs],
                    ).model_dump())

                qs = urlparse(url).query
                if qs:
                    for pair in qs.split("&"):
                        parts = pair.split("=", 1)
                        if len(parts) == 2:
                            params.append(ParamData(
                                host=host, url=url, name=parts[0], original_value=parts[1],
                            ).model_dump())

            except Exception:
                pass

        return CrawlResult(
            pages_visited=len(visited),
            forms=forms,
            params=params,
            links=sorted(visited),
        ), reqs

    @staticmethod
    def _resolve_link(link: str, base_url: str, host: str) -> Optional[str]:
        if link.startswith("http"):
            parsed = urlparse(link)
            if parsed.hostname and (parsed.hostname == host or parsed.hostname.endswith(f".{host}")):
                return link
            return None
        if link.startswith("/"):
            origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).hostname}"
            return f"{origin}{link}"
        if link.startswith(("javascript:", "mailto:", "data:")):
            return None
        return f"{base_url.rsplit('/', 1)[0]}/{link}"

    # ------------------------------------------------------------------
    # Parameter fuzzer
    # ------------------------------------------------------------------

    async def _fuzz(self, client, crawl: CrawlResult, host, ctx):
        findings: list[dict] = []
        reqs = 0

        for param in (crawl.params if isinstance(crawl, CrawlResult) else crawl.get("params", []))[:20]:
            p = param if isinstance(param, dict) else param.model_dump()
            try:
                async with ctx.throttle.acquire("fuzz"):
                    baseline = await client.get(p["url"], timeout=5.0)
                    reqs += 1
            except Exception:
                continue

            for payload_name, payload_value in FUZZ_PAYLOADS.items():
                try:
                    test_url = p["url"].replace(
                        f"{p['name']}={p['original_value']}",
                        f"{p['name']}={payload_value}",
                    )
                    async with ctx.throttle.acquire("fuzz"):
                        resp = await client.get(test_url, follow_redirects=False, timeout=5.0)
                        reqs += 1

                    body = resp.text

                    if payload_value in body and payload_value not in baseline.text:
                        findings.append(FuzzFinding(
                            host=host, url=test_url, parameter=p["name"],
                            payload_type=payload_name, payload=payload_value,
                            detection="reflected",
                            evidence=f"Payload '{payload_value}' reflected in response",
                            severity="high" if "xss" in payload_name else "medium",
                            confidence=0.85,
                        ).model_dump())

                    if payload_name == "ssti_probe" and "49" in body and "49" not in baseline.text:
                        findings.append(FuzzFinding(
                            host=host, url=test_url, parameter=p["name"],
                            payload_type="ssti", payload=payload_value,
                            detection="ssti_evaluated",
                            evidence="{{7*7}} evaluated to 49",
                            severity="critical", confidence=0.95,
                        ).model_dump())

                    if payload_name == "open_redirect" and resp.status_code in (301, 302):
                        loc = resp.headers.get("location", "")
                        if "evil.example.com" in loc:
                            findings.append(FuzzFinding(
                                host=host, url=test_url, parameter=p["name"],
                                payload_type="open_redirect", payload=payload_value,
                                detection="redirect_to_external",
                                evidence=f"Redirect to {loc}",
                                severity="medium", confidence=0.90,
                            ).model_dump())

                    error_sigs = ["Traceback", "SQL syntax", "mysql_", "ORA-", "SQLSTATE",
                                 "Exception in", "Fatal error", "Parse error"]
                    for sig in error_sigs:
                        if sig in body and sig not in baseline.text:
                            findings.append(FuzzFinding(
                                host=host, url=test_url, parameter=p["name"],
                                payload_type=payload_name, payload=payload_value,
                                detection="error_triggered",
                                evidence=f"Error signature '{sig}' after injection",
                                severity="high", confidence=0.80,
                            ).model_dump())
                            break

                except Exception:
                    pass

        return findings, reqs

    # ------------------------------------------------------------------
    # GraphQL tester
    # ------------------------------------------------------------------

    async def _test_graphql(self, client, ctx):
        findings: list[dict] = []
        reqs = 0
        gql_hosts = ctx.hosts_for_graphql_deep or set()

        for wp in (ctx.web_profiles or []):
            w = wp if isinstance(wp, dict) else {}
            for schema in w.get("api_schemas_found", []):
                if (schema if isinstance(schema, dict) else {}).get("path") == "/graphql":
                    gql_hosts.add(w.get("host", ""))

        for host in list(gql_hosts)[:5]:
            endpoint = f"https://{host}/graphql"
            try:
                async with ctx.throttle.acquire("http_probe"):
                    resp = await client.post(
                        endpoint,
                        json={"query": "{ __schema { queryType { name } mutationType { name } types { name kind } } }"},
                        timeout=10.0,
                    )
                    reqs += 1
                    if resp.status_code == 200:
                        data = resp.json()
                        if "data" in data and "__schema" in (data.get("data") or {}):
                            types = [t["name"] for t in data["data"]["__schema"].get("types", []) if not t["name"].startswith("__")]
                            findings.append(GraphQLFinding(
                                endpoint=endpoint,
                                finding="introspection_enabled",
                                severity="high",
                                evidence=f"Full schema: {len(types)} types exposed",
                                confidence=1.0,
                                schema_types=types[:30],
                            ).model_dump())

                async with ctx.throttle.acquire("http_probe"):
                    depth_q = "{ user { friends { friends { friends { friends { id } } } } } }"
                    resp2 = await client.post(endpoint, json={"query": depth_q}, timeout=5.0)
                    reqs += 1
                    if resp2.status_code == 200 and "errors" not in resp2.json():
                        findings.append(GraphQLFinding(
                            endpoint=endpoint,
                            finding="no_depth_limit",
                            severity="medium",
                            evidence="Deeply nested query accepted",
                            confidence=0.75,
                        ).model_dump())

            except Exception:
                pass

        return findings, reqs

    # ------------------------------------------------------------------
    # Exploit chain detector
    # ------------------------------------------------------------------

    def _detect_chains(self, ctx: ScanContext, fuzz_findings: list[dict]) -> list[dict]:
        chains: list[dict] = []

        admin_exposed = any(
            (h if isinstance(h, dict) else {}).get("finding_type") == "admin_panel"
            for h in (ctx.hidden_findings or [])
        )
        has_waf = any(
            (i if isinstance(i, dict) else {}).get("waf_detected")
            for i in (ctx.cdn_waf_intel or [])
        )
        hndl_hosts = [
            (c if isinstance(c, dict) else {}).get("host")
            for c in (ctx.crypto_findings or [])
            if (c if isinstance(c, dict) else {}).get("hndl_risk")
        ]
        has_api = any(
            len((w if isinstance(w, dict) else {}).get("api_schemas_found", [])) > 0
            for w in (ctx.web_profiles or [])
        )
        has_xss = any(f.get("payload_type") == "xss_probe" and f.get("detection") == "reflected" for f in fuzz_findings)
        cookie_no_httponly = any(
            not c.get("http_only", True)
            for w in (ctx.web_profiles or [])
            for c in (w if isinstance(w, dict) else {}).get("cookies", [])
            if any(kw in (c.get("name") or "").lower() for kw in ("session", "sid", "token"))
        )

        for pat in CHAIN_PATTERNS:
            conds = pat["conditions"]
            matched = True
            match_data: dict = {}

            if "hidden_type" in conds:
                if not any(
                    (h if isinstance(h, dict) else {}).get("finding_type") == conds["hidden_type"]
                    for h in (ctx.hidden_findings or [])
                ):
                    matched = False
                else:
                    for h in (ctx.hidden_findings or []):
                        hd = h if isinstance(h, dict) else {}
                        if hd.get("finding_type") == conds["hidden_type"]:
                            match_data["path"] = hd.get("path", "")
                            match_data["host"] = hd.get("host", "")
                            break

            if "waf" in conds and conds["waf"] is False and has_waf:
                matched = False
            if conds.get("hndl") and not hndl_hosts:
                matched = False
            if conds.get("has_api") and not has_api:
                matched = False
            if conds.get("fuzz_xss") and not has_xss:
                matched = False
            if conds.get("cookie_no_httponly") and not cookie_no_httponly:
                matched = False

            if matched:
                narrative = pat["narrative"]
                for k, v in match_data.items():
                    narrative = narrative.replace("{" + k + "}", str(v))
                if hndl_hosts:
                    narrative = narrative.replace("{host}", hndl_hosts[0] or ctx.domain)

                chains.append(ExploitChain(
                    chain_id=pat["id"],
                    name=pat["name"],
                    severity=pat["severity"],
                    description=pat["name"],
                    narrative=narrative,
                    steps=[match_data.get("path", ""), f"WAF: {'yes' if has_waf else 'no'}"],
                    affected_hosts=[match_data.get("host", ctx.domain)],
                    confidence=0.7,
                    remediation=pat["remediation"],
                ).model_dump())

        return chains
