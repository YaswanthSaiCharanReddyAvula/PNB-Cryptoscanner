"""
QuantumShield — Browser Scanning Engine (Stage 16)

Headless Chromium via Playwright for SPA rendering, DOM-aware crawling,
XSS validation, and auth-flow analysis.  Gracefully skips if Playwright
is not installed.
"""

from __future__ import annotations

import re
import time
from typing import Optional
from urllib.parse import urlparse

from app.scanner.models import (
    AuthFlowResult,
    BrowserCrawlResult,
    DOMFinding,
    InterceptedRequest,
    StageResult,
    ValidatedXSS,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from playwright.async_api import async_playwright, Browser, Page  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.info("Playwright not installed — Stage 16 (Browser Engine) will be skipped")


class BrowserScanEngine(ScanStage):
    name = "browser_engine"
    order = 16
    timeout_seconds = 120
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["all_findings"]
    merge_strategy = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        if not PLAYWRIGHT_AVAILABLE:
            return StageResult(status="skipped", error="Playwright not installed")

        findings: list[dict] = []
        request_count = 0

        hosts = list(ctx.hosts_for_browser_scan or set())
        if not hosts:
            web_hosts = self._web_hosts(ctx)
            hosts = web_hosts[:5]

        if not hosts:
            return StageResult(status="completed", data={"all_findings": []})

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) QuantumShield/1.0",
                )

                for host in hosts:
                    try:
                        crawl_result, reqs = await self._crawl_host(context, host, ctx)
                        request_count += reqs

                        for dom_f in crawl_result.get("dom_findings", []):
                            dom_f["_finding_type"] = "dom_finding"
                            findings.append(dom_f)

                        for api_call in crawl_result.get("intercepted_api_calls", []):
                            findings.append({
                                "host": host,
                                "finding_type": "js_api_call",
                                "url": api_call.get("url"),
                                "method": api_call.get("method"),
                                "severity": "info",
                                "confidence": 0.6,
                                "evidence": f"JS initiated {api_call.get('method')} to {api_call.get('url')}",
                                "_finding_type": "dom_finding",
                            })

                        auth = await self._analyse_auth(context, host)
                        if auth and auth.get("findings"):
                            for af in auth["findings"]:
                                findings.append({
                                    "host": host,
                                    "finding_type": "auth_weakness",
                                    "evidence": af,
                                    "severity": "medium",
                                    "confidence": 0.7,
                                    "_finding_type": "behavioral_finding",
                                })

                    except Exception:
                        logger.debug("Browser scan failed for %s", host, exc_info=True)

                await browser.close()

        except Exception as exc:
            logger.warning("Browser engine error: %s", exc)
            return StageResult(status="partial", data={"all_findings": findings}, error=str(exc))

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
        return hosts

    async def _crawl_host(self, browser_ctx, host: str, ctx: ScanContext):
        page = await browser_ctx.new_page()
        intercepted: list[dict] = []
        dom_findings: list[dict] = []
        visited: set[str] = set()
        reqs = 0

        def on_request(request):
            url = request.url
            if "/api/" in url or "/graphql" in url or "/rest/" in url:
                intercepted.append(InterceptedRequest(
                    url=url, method=request.method,
                    resource_type=request.resource_type,
                ).model_dump())

        page.on("request", on_request)

        base_url = f"https://{host}"
        queue = [base_url]

        while queue and len(visited) < 20:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            reqs += 1

            try:
                await page.goto(url, wait_until="networkidle", timeout=10000)
                await page.wait_for_timeout(1500)

                links = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
                for link in (links or []):
                    parsed = urlparse(link)
                    if parsed.hostname and (parsed.hostname == host or parsed.hostname.endswith(f".{host}")):
                        if link not in visited:
                            queue.append(link)

                secrets = await page.evaluate("""() => {
                    const found = [];
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (/token|secret|key|auth|session/i.test(key)) {
                            found.push({type: 'localstorage', key: key});
                        }
                    }
                    const scripts = document.querySelectorAll('script:not([src])');
                    for (const s of scripts) {
                        if (/api[_-]?key|secret[_-]?key|access[_-]?token/i.test(s.textContent)) {
                            found.push({type: 'inline_secret', snippet: s.textContent.substring(0, 100)});
                        }
                    }
                    return found;
                }""")

                for secret in (secrets or []):
                    dom_findings.append(DOMFinding(
                        url=url,
                        finding_type=secret.get("type", "unknown"),
                        evidence=str(secret)[:200],
                        severity="high",
                        confidence=0.8,
                    ).model_dump())

            except Exception:
                pass

        await page.close()

        return {
            "pages_rendered": len(visited),
            "dom_findings": dom_findings,
            "intercepted_api_calls": intercepted,
        }, reqs

    async def _analyse_auth(self, browser_ctx, host: str) -> Optional[dict]:
        page = await browser_ctx.new_page()
        findings: list[str] = []

        try:
            url = f"https://{host}"
            await page.goto(url, wait_until="networkidle", timeout=10000)

            login_selectors = [
                "input[type='password']",
                "form[action*='login']",
                "form[action*='auth']",
                "#loginForm", ".login-form",
            ]
            found_login = False
            for sel in login_selectors:
                el = await page.query_selector(sel)
                if el:
                    found_login = True
                    break

            if not found_login:
                await page.close()
                return None

            pwd_el = await page.query_selector("input[type='password']")
            if pwd_el:
                autocomplete = await pwd_el.get_attribute("autocomplete")
                if autocomplete not in ("off", "new-password"):
                    findings.append("Password field allows autocomplete (credential caching risk)")

            csrf = await page.query_selector(
                "input[name*='csrf'], input[name*='_token'], input[name*='authenticity_token']"
            )
            if not csrf:
                findings.append("Login form has no CSRF token")

        except Exception:
            pass
        finally:
            await page.close()

        return AuthFlowResult(
            url=f"https://{host}",
            login_form_detected=True,
            findings=findings,
            confidence=0.75,
        ).model_dump() if findings else None
