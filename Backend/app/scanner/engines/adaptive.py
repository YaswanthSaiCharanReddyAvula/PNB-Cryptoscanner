"""
QuantumShield — Adaptive Rate Controller + Behavioral Analyzer (Stage 15)

AdaptiveRateController monitors response patterns and adjusts scanning
speed per-host. BehavioralAnalyzer runs active behavioural probes in
aggressive mode.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

import httpx

from app.scanner.models import BehavioralFinding, HostRateState, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.scanner.throttle import ThrottleController
from app.utils.logger import get_logger

logger = get_logger(__name__)


# =====================================================================
# Adaptive Rate Controller (always active — wraps ThrottleController)
# =====================================================================

class AdaptiveRateController(ThrottleController):
    """Extends ThrottleController with per-host adaptive delay logic."""

    def __init__(self) -> None:
        super().__init__()
        self.host_state: dict[str, HostRateState] = {}
        self.global_backoff: float = 0.0

    def _state(self, host: str) -> HostRateState:
        if host not in self.host_state:
            self.host_state[host] = HostRateState()
        return self.host_state[host]

    async def record_response(self, host: str, status: int, response_time: float) -> None:
        st = self._state(host)
        st.total_requests += 1
        st.response_times.append(response_time)
        if len(st.response_times) > 100:
            st.response_times = st.response_times[-100:]

        if status == 429:
            st.rate_limit_hits += 1
            st.current_delay = min(st.current_delay * 2 + 1.0, 30.0)
            st.concurrency_reduction += 1
            await self._reduce_concurrency("http_probe", 0.5)

        if status == 403:
            st.waf_blocks += 1
            if st.waf_blocks > 3 and st.waf_blocks / max(st.total_requests, 1) > 0.3:
                st.current_delay = min(st.current_delay + 2.0, 20.0)
                st.waf_triggered = True

        if status == 0:
            st.timeouts += 1
            if st.timeouts > 5:
                st.current_delay = min(st.current_delay + 5.0, 60.0)

        if len(st.response_times) >= 10:
            recent = st.response_times[-10:]
            if all(t < 2.0 for t in recent) and st.current_delay > 0:
                st.current_delay = max(0, st.current_delay - 0.5)

    async def wait_before_request(self, host: str) -> None:
        st = self.host_state.get(host)
        delay = (st.current_delay if st else 0) + self.global_backoff
        if delay > 0:
            jitter = delay * 0.2 * (hash(host) % 100 / 100.0)
            await asyncio.sleep(delay + jitter)

    async def _reduce_concurrency(self, category: str, factor: float) -> None:
        old = self.category_semaphores.get(category)
        if old is None:
            return
        new_limit = max(1, int(getattr(old, "_value", 10) * factor))
        self.category_semaphores[category] = asyncio.Semaphore(new_limit)
        logger.info("Reduced %s concurrency to %d", category, new_limit)


# =====================================================================
# Behavioral Analyzer (Stage 15 — aggressive mode only)
# =====================================================================

class BehavioralAnalyzer(ScanStage):
    name = "behavioral"
    order = 15
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["services"]
    writes_fields = ["all_findings"]
    merge_strategy = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        findings: list[dict] = []
        request_count = 0
        web_hosts = self._get_web_hosts(ctx)

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
            for host in web_hosts[:30]:
                url = f"https://{host}"
                try:
                    host_findings, reqs = await self._analyse_host(client, host, url, ctx)
                    findings.extend(host_findings)
                    request_count += reqs
                except Exception:
                    logger.debug("Behavioral analysis skipped for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"all_findings": findings},
            request_count=request_count,
        )

    @staticmethod
    def _get_web_hosts(ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            if s.get("protocol_category") == "web" or s.get("port") in (80, 443, 8080, 8443):
                h = s.get("host", "")
                if h and h not in hosts:
                    hosts.append(h)
        return hosts

    async def _analyse_host(self, client: httpx.AsyncClient, host: str, url: str, ctx: ScanContext):
        findings: list[dict] = []
        reqs = 0

        for test_fn in (
            self._test_xff_trust,
            self._test_ua_cloaking,
            self._test_method_tampering,
            self._test_host_header_injection,
        ):
            try:
                async with ctx.throttle.acquire("http_probe"):
                    result, r = await test_fn(client, host, url)
                    reqs += r
                    if result:
                        findings.extend(result if isinstance(result, list) else [result])
            except Exception:
                pass

        return findings, reqs

    async def _test_xff_trust(self, client, host, url):
        r1 = await client.get(url)
        r2 = await client.get(url, headers={"X-Forwarded-For": "127.0.0.1"})
        if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) > 500:
            return BehavioralFinding(
                host=host, test="xff_trust",
                evidence="Response changed with X-Forwarded-For: 127.0.0.1",
                severity="medium", confidence=0.7,
                implication="Server may trust X-Forwarded-For for access control",
            ).model_dump(), 2
        return None, 2

    async def _test_ua_cloaking(self, client, host, url):
        ua_bot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ua_user = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        r1 = await client.get(url, headers={"User-Agent": ua_bot})
        r2 = await client.get(url, headers={"User-Agent": ua_user})
        diff = abs(len(r1.text) - len(r2.text))
        if diff > 1000:
            return BehavioralFinding(
                host=host, test="ua_cloaking",
                evidence=f"Response size differs by {diff} bytes between bot and browser UA",
                severity="low", confidence=0.5,
                implication="Server serves different content to crawlers vs browsers",
            ).model_dump(), 2
        return None, 2

    async def _test_method_tampering(self, client, host, url):
        findings = []
        for method in ("TRACE", "PUT", "DELETE"):
            try:
                resp = await client.request(method, url, timeout=3.0)
                if method == "TRACE" and resp.status_code == 200:
                    findings.append(BehavioralFinding(
                        host=host, test="trace_enabled",
                        evidence="HTTP TRACE returns 200 OK",
                        severity="medium", confidence=0.9,
                        implication="TRACE enabled — potential XST vector",
                    ).model_dump())
                elif method in ("PUT", "DELETE") and resp.status_code in (200, 201, 204):
                    findings.append(BehavioralFinding(
                        host=host, test=f"{method.lower()}_allowed",
                        evidence=f"HTTP {method} on / returns {resp.status_code}",
                        severity="high", confidence=0.6,
                        implication=f"Dangerous method {method} may be enabled",
                    ).model_dump())
            except Exception:
                pass
        return findings or None, 3

    async def _test_host_header_injection(self, client, host, url):
        try:
            resp = await client.get(url, headers={"Host": "evil.example.com"})
            if "evil.example.com" in resp.text:
                return BehavioralFinding(
                    host=host, test="host_header_injection",
                    evidence="Injected Host header reflected in response body",
                    severity="high", confidence=0.85,
                    implication="Host header injection — potential cache poisoning",
                ).model_dump(), 1
        except Exception:
            pass
        return None, 1
