---
name: Custom Scanner Final Design
overview: Final merged design that eliminates ALL external scanner dependencies (nmap, subfinder, amass, testssl, sslscan, zgrab2, nuclei, openssl CLI) and replaces them with custom Python implementations using only stdlib + dnspython + cryptography + httpx.
todos: []
isProject: false
---

# QuantumShield -- Final Custom Scanner Engine Design

---

## 0. Deep Comparison: External Dependencies to Kill

### Dependencies in the Claude Blueprint that must go


| Blueprint section | External dependency used   | Where in current code                | Replacement                                     |
| ----------------- | -------------------------- | ------------------------------------ | ----------------------------------------------- |
| Recon Engine      | `subfinder` subprocess     | `asset_discovery.py:run_subfinder()` | Custom CT log + DNS brute-force + DNS zone walk |
| Recon Engine      | `amass` subprocess         | `asset_discovery.py:run_amass()`     | Same custom pipeline (CT + brute-force)         |
| Recon Engine      | `dnsx` subprocess          | `asset_discovery.py:run_dnsx()`      | `dnspython` async resolver liveness check       |
| Recon Engine      | `httpx-toolkit` subprocess | `asset_discovery.py:run_httpx()`     | `httpx` Python library (already a dependency)   |
| Network Engine    | `nmap` subprocess          | `asset_discovery.py:scan_ports()`    | Custom async TCP connect scanner                |
| TLS Engine        | `sslscan` subprocess       | `tls_scanner.py:_run_sslscan()`      | Custom `ssl.SSLContext` cipher probing          |
| TLS Engine        | `testssl` subprocess       | `tls_scanner.py:_run_testssl()`      | Custom TLS version + cipher enumeration         |
| TLS Engine        | `zgrab2` subprocess        | `tls_scanner.py:_run_zgrab2()`       | Custom TLS handshake via `ssl` stdlib           |
| TLS Engine        | `openssl` subprocess       | `tls_scanner.py:_run_openssl()`      | `cryptography` library cert parsing             |
| TLS Engine        | `sh -c` shell wrapper      | `tls_scanner.py`                     | Eliminated (no shell needed)                    |
| Vuln Engine       | `nuclei` subprocess        | `vuln_scanner.py:run_nuclei_scan()`  | Custom rule-based vulnerability engine          |


### Dependencies in the Cursor doc that must go

The Cursor doc (`new Scanner Engine Docs.md`) **still proposed keeping** nmap with `-sV` added, and still relied on `testssl`/`openssl` for STARTTLS. These must all be replaced.

**Total external binaries eliminated: 9** (subfinder, amass, dnsx, httpx-toolkit, nmap, sslscan, testssl, zgrab2, nuclei). Only `openssl` remains as an optional fallback (never required).

### Python libraries retained (these are libraries, not external tool binaries)

- `dnspython` -- pure Python DNS resolver (async)
- `cryptography` -- pure Python cert/key parsing
- `httpx` -- async HTTP client (already in `requirements.txt`)
- `ssl` -- Python stdlib TLS
- `asyncio` -- Python stdlib async

---

## 1. Final Architecture

### System diagram

```
Frontend (React + Vite + Electron)
    |
    | REST + WebSocket
    v
FastAPI Gateway (/api/v1)
    |
    v
Scan Orchestrator (PipelineManager)
    |-- ThrottleController (per-stage semaphores)
    |-- RetryManager (exponential backoff, circuit breaker)
    |-- WebSocket progress emitter
    |
    v (runs 12 stages sequentially)
+--------------------------------------------------+
| STAGE 1: Surface Recon Engine                     |
|   DNS sweep, CT logs, subdomain brute, WHOIS,     |
|   reverse DNS, zone transfer attempt               |
+--------------------------------------------------+
| STAGE 2: Network Scan Engine                       |
|   Async TCP connect scanner, banner grab,          |
|   service fingerprint, ASN/BGP via DNS             |
+--------------------------------------------------+
| STAGE 3: OS Fingerprint Engine                     |
|   Banner inference, HTTP header OS hints,          |
|   TTL analysis, container indicators               |
+--------------------------------------------------+
| STAGE 4: TLS / Crypto Engine                       |
|   Custom TLS version probe, cipher enumeration,    |
|   cert chain extraction, OCSP/SCT, STARTTLS        |
+--------------------------------------------------+
| STAGE 5: Crypto Analysis Engine                    |
|   Algorithm classification, PQC risk tagging,      |
|   HNDL assessment, NIST mapping                    |
+--------------------------------------------------+
| STAGE 6: CDN / WAF / Proxy Detection Engine       |
|   CNAME-based CDN, header-based WAF,               |
|   cloud IP ranges, proxy detection                  |
+--------------------------------------------------+
| STAGE 7: Tech Fingerprint Engine                   |
|   Headers, HTML meta, script/link analysis,        |
|   cookie names, favicon hash, error pages           |
+--------------------------------------------------+
| STAGE 8: Web / API Discovery Engine               |
|   Security headers, cookies, CORS, API schema,     |
|   well-known URIs, form detection                   |
+--------------------------------------------------+
| STAGE 9: Hidden Discovery Engine                   |
|   robots.txt, sitemap, path brute-force,           |
|   backup files, admin panels, JS route extraction   |
+--------------------------------------------------+
| STAGE 10: Vulnerability Engine                     |
|   Rule-based vuln matching, CVE correlation,       |
|   behavioral probes, misconfig detection            |
+--------------------------------------------------+
| STAGE 11: Correlation + Risk Scoring Engine       |
|   Asset graph build, attack path detection,        |
|   per-asset + estate scoring, scan diff             |
+--------------------------------------------------+
| STAGE 12: CBOM + Report Engine                    |
|   CERT-IN CBOM, recommendations, export bundles,   |
|   executive summary, machine-readable outputs       |
+--------------------------------------------------+
    |
    v
MongoDB (scans, assets, findings, graph, cbom)
```

---

## 2. Folder Structure

```
Backend/app/
  scanner/                          # NEW package
    __init__.py
    pipeline.py                     # PipelineManager, ScanStage base, ScanContext
    throttle.py                     # ThrottleController
    retry.py                        # RetryManager, CircuitBreaker
    models.py                       # All new Pydantic models for the engine
    engines/
      __init__.py
      recon.py                      # SurfaceReconEngine
      network.py                    # NetworkScanEngine
      os_fingerprint.py             # OSFingerprintEngine
      tls_engine.py                 # TLSCryptoEngine (replaces tls_scanner.py)
      crypto_analysis.py            # CryptoAnalysisEngine (replaces crypto_analyzer.py)
      cdn_waf.py                    # CDNWAFEngine
      tech_fingerprint.py           # TechFingerprintEngine
      web_discovery.py              # WebAPIDiscoveryEngine
      hidden_discovery.py           # HiddenDiscoveryEngine
      vuln_engine.py                # VulnerabilityEngine (replaces vuln_scanner.py + cve_mapper.py)
      correlation.py                # CorrelationGraphEngine + RiskScoringEngine
      reporting.py                  # CBOMReportEngine
    data/
      subdomain_wordlist.txt        # ~500 high-value subdomain prefixes
      common_paths.txt              # ~300 hidden path probes
      tech_signatures.json          # Wappalyzer-style fingerprint rules
      service_signatures.json       # Banner -> service matching rules
      cloud_ip_ranges.json          # AWS/Azure/GCP/Cloudflare CIDRs
      vuln_rules.json               # Custom vulnerability detection rules
      cipher_registry.json          # Complete cipher suite metadata
```

Old modules in `app/modules/` are **kept as-is** for backward compatibility. The new `app/scanner/` package is the custom engine. Routes in `app/api/routes.py` are updated to call `PipelineManager` instead of the hardcoded 8-stage pipeline.

---

## 3. Core Infrastructure

### 3.0 Operational Rules (MANDATORY)

These rules are enforced across every engine and every stage. Violations are bugs.

**Rule 1: Throttle enforcement.** ALL async operations (DNS, TCP, HTTP, TLS, fuzzing) MUST acquire a semaphore from ThrottleController before execution. Direct `asyncio.gather` without throttling is prohibited. Every network call goes through `ctx.throttle.acquire(category)`.

**Rule 2: Global concurrency cap.** Every operation must acquire BOTH the global semaphore (500 total in-flight operations across all stages) AND the category semaphore. This prevents scan explosion regardless of how many stages are active.

**Rule 3: Memory discipline.** Large data (HTTP response bodies, banners, HTML content) MUST NOT be stored in ScanContext. They are either (a) streamed directly to MongoDB, or (b) truncated to 64KB max before storing. Context holds only structured summaries: hostnames, ports, finding objects, scores.

**Rule 4: Streaming persistence.** After EACH stage completes, results are persisted to MongoDB immediately. Temporary buffers (raw responses, intermediate lists) are cleared. Context retains only the summarized fields needed by downstream stages.

**Rule 5: Stage input validation.** Every stage declares `required_fields`. Before execution, the pipeline checks that context contains the required data. If missing (because an upstream stage failed), the stage is skipped with status `"skipped"` and reason logged.

**Rule 6: Failure propagation.** Stages have criticality levels: `CRITICAL` (Recon, Network), `IMPORTANT` (TLS, Web, Crypto), `OPTIONAL` (Advanced, Browser, AI). If a CRITICAL stage fails, all downstream dependent stages are marked `"skipped"`. IMPORTANT stage failure marks only its direct dependents as skipped. OPTIONAL stage failure never blocks anything.

**Rule 7: Merge contracts.** Each stage declares which context fields it writes and its merge strategy: `append` (add to list), `overwrite` (replace entirely), or `deduplicate` (add only new items, keyed by host+port or host+path). No implicit mutation.

### 3.1 PipelineManager -- `app/scanner/pipeline.py`

```python
from pydantic import BaseModel
from typing import Callable, Any, Optional
import asyncio, time, hashlib, json
from app.utils.logger import get_logger

logger = get_logger(__name__)

class StageResult(BaseModel):
    status: str              # "completed" | "partial" | "timeout" | "error" | "skipped"
    data: dict = {}
    error: Optional[str] = None
    request_count: int = 0   # how many network requests this stage made
    duration_seconds: float = 0.0

class ScanContext:
    """Mutable state passed through all stages."""
    scan_id: str
    domain: str
    options: dict
    # Accumulated results (summaries only -- no raw bodies)
    subdomains: list[str]
    ip_map: dict[str, list[str]]
    dns_records: list
    whois: Optional[Any]
    assets: list
    services: list
    os_fingerprints: list
    tls_profiles: list
    crypto_findings: list
    cdn_waf_intel: list
    tech_fingerprints: list
    web_profiles: list
    hidden_findings: list
    vuln_findings: list
    all_findings: list       # unified list for filtering
    graph: Optional[Any]
    risk_scores: list
    # Adaptive state (set by AI engine / scheduler)
    extra_hidden_paths: list[str]
    hosts_for_full_cipher_enum: set[str]
    hosts_for_browser_scan: set[str]
    hosts_for_deep_fuzz: set[str]
    hosts_for_graphql_deep: set[str]
    hosts_for_auth_test: set[str]
    deprioritized_hosts: set[str]
    active_hosts: list[str]   # filtered by scheduler for current stage
    all_hosts: list[str]
    # Infrastructure (not persisted)
    throttle: "ThrottleController"
    broadcast: Callable
    db: Any

    def has(self, fields: list[str]) -> bool:
        """Check whether all required fields are populated."""
        for f in fields:
            val = getattr(self, f, None)
            if val is None or (isinstance(val, (list, dict)) and len(val) == 0):
                return False
        return True

class StageCriticality:
    CRITICAL = "critical"     # Recon, Network -- failure blocks everything
    IMPORTANT = "important"   # TLS, Crypto, Web -- failure blocks dependents
    OPTIONAL = "optional"     # Advanced, Browser, AI -- failure blocks nothing

class MergeStrategy:
    APPEND = "append"
    OVERWRITE = "overwrite"
    DEDUPLICATE = "deduplicate"

class ScanStage:
    name: str
    order: int
    timeout_seconds: int = 120
    max_retries: int = 1
    criticality: str = StageCriticality.IMPORTANT
    required_fields: list[str] = []       # fields that must exist in ctx
    writes_fields: list[str] = []         # fields this stage produces
    merge_strategy: str = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        raise NotImplementedError

# Per-stage timeout table
STAGE_TIMEOUTS = {
    "recon":               60,
    "network":             120,
    "os_fingerprint":      45,
    "tls_engine":          90,
    "crypto_analysis":     30,
    "cdn_waf":             45,
    "tech_fingerprint":    45,
    "web_discovery":       60,
    "hidden_discovery":    90,
    "vuln_engine":         60,
    "correlation":         30,
    "reporting":           30,
    "advanced_fingerprint":60,
    "attack_surface":      180,
    "behavioral":          60,
    "browser_engine":      120,
}

class PipelineManager:
    def __init__(self, stages: list[ScanStage], ai_adaptive=None, scheduler=None):
        self.stages = sorted(stages, key=lambda s: s.order)
        self.retry = RetryManager()
        self.ai = ai_adaptive
        self.scheduler = scheduler
        self.metrics: list[StageMetrics] = []

    async def run(self, ctx: ScanContext) -> dict:
        skipped_due_to: set[str] = set()

        for stage in self.stages:
            # Input validation: check required fields
            if stage.required_fields and not ctx.has(stage.required_fields):
                logger.warning("Stage %s skipped: missing required fields %s",
                              stage.name, stage.required_fields)
                self.metrics.append(StageMetrics(
                    name=stage.name, status="skipped",
                    reason="missing required fields"))
                if stage.criticality == StageCriticality.CRITICAL:
                    skipped_due_to.add(stage.name)
                continue

            # Check if upstream CRITICAL stage failed
            if any(dep in skipped_due_to for dep in stage.required_fields):
                logger.warning("Stage %s skipped: upstream critical dependency failed",
                              stage.name)
                self.metrics.append(StageMetrics(
                    name=stage.name, status="skipped",
                    reason="upstream dependency failed"))
                continue

            # Scheduler: early stopping check
            if self.scheduler and not self.scheduler.should_continue():
                logger.info("Early stopping triggered at stage %s", stage.name)
                break

            # Scheduler: filter hosts for expensive stages
            if self.scheduler and stage.order >= 13:
                ctx.active_hosts = self.scheduler.filter_by_tier(
                    ctx.all_hosts, min_tier="high")
            elif self.scheduler and stage.order >= 9:
                ctx.active_hosts = self.scheduler.filter_by_tier(
                    ctx.all_hosts, min_tier="standard")

            # Broadcast progress
            await ctx.broadcast(ctx.scan_id, {
                "type": "stage", "stage": stage.order,
                "name": stage.name, "status": "running",
                "progress": int((stage.order / len(self.stages)) * 100)
            })

            # Execute with retry
            t0 = time.time()
            result = await self.retry.execute(
                stage, ctx, max_retries=stage.max_retries
            )
            duration = time.time() - t0

            # Log metrics
            self.metrics.append(StageMetrics(
                name=stage.name, status=result.status,
                duration=duration, request_count=result.request_count,
                error=result.error))

            # Handle failures
            if result.status in ("error", "timeout"):
                if stage.criticality == StageCriticality.CRITICAL:
                    skipped_due_to.add(stage.name)
                    logger.error("CRITICAL stage %s failed: %s", stage.name, result.error)
                elif stage.criticality == StageCriticality.IMPORTANT:
                    for dep_stage in self.stages:
                        if stage.name in [f.split(".")[0] for f in dep_stage.required_fields]:
                            skipped_due_to.add(dep_stage.name)

            # Merge results into context (per stage contract)
            if result.status in ("completed", "partial"):
                self._merge(ctx, stage, result)

            # Persist immediately, then clear temp buffers
            await self._persist_stage(ctx, stage.name, result)

            # Update scheduler request count
            if self.scheduler:
                self.scheduler.request_count += result.request_count

            # AI adaptive hook
            if self.ai and ctx.options.get("ai_adaptive", True):
                actions = await self.ai.analyze_and_decide(
                    stage.name,
                    self._summarize_stage_findings(stage.name, result),
                    self._summarize_context(ctx),
                )
                await self._execute_adaptive_actions(ctx, actions)

        # Final confidence filtering
        if self.scheduler:
            from app.scanner.engines.scheduler import ConfidenceFilter
            ctx.all_findings = ConfidenceFilter().filter(
                ctx.all_findings, ctx.options.get("scan_depth", "standard"))

        return self._build_final(ctx)

    def _merge(self, ctx: ScanContext, stage: ScanStage, result: StageResult):
        """Merge stage output into context per declared contract."""
        for field in stage.writes_fields:
            new_data = result.data.get(field)
            if new_data is None:
                continue
            existing = getattr(ctx, field, None)
            if stage.merge_strategy == MergeStrategy.OVERWRITE or existing is None:
                setattr(ctx, field, new_data)
            elif stage.merge_strategy == MergeStrategy.APPEND and isinstance(existing, list):
                existing.extend(new_data if isinstance(new_data, list) else [new_data])
            elif stage.merge_strategy == MergeStrategy.DEDUPLICATE and isinstance(existing, list):
                existing_keys = {self._dedup_key(item) for item in existing}
                for item in (new_data if isinstance(new_data, list) else [new_data]):
                    if self._dedup_key(item) not in existing_keys:
                        existing.append(item)

    @staticmethod
    def _dedup_key(item) -> str:
        if isinstance(item, dict):
            return f"{item.get('host','')}-{item.get('port','')}-{item.get('path','')}"
        return str(item)

class StageMetrics(BaseModel):
    name: str
    status: str
    duration: float = 0.0
    request_count: int = 0
    error: Optional[str] = None
    reason: Optional[str] = None
```

### 3.2 RetryManager + CircuitBreaker -- `app/scanner/retry.py`

```python
import asyncio, time, random

class CircuitBreaker:
    """
    Per-stage circuit breaker.
    - CLOSED: normal operation
    - OPEN: stage has failed too many times, skip immediately
    - HALF_OPEN: try one request to see if it recovers
    """
    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 60.0):
        self.state: str = "closed"        # closed | open | half_open
        self.failure_count: int = 0
        self.failure_threshold = failure_threshold
        self.last_failure_time: float = 0.0
        self.recovery_timeout = recovery_timeout

    def record_success(self):
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"

    def should_allow(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                return True
            return False
        # half_open: allow one attempt
        return True


class RetryManager:
    def __init__(self):
        self.breakers: dict[str, CircuitBreaker] = {}

    def _get_breaker(self, stage_name: str) -> CircuitBreaker:
        if stage_name not in self.breakers:
            self.breakers[stage_name] = CircuitBreaker()
        return self.breakers[stage_name]

    async def execute(self, stage, ctx, max_retries=1) -> StageResult:
        breaker = self._get_breaker(stage.name)

        if not breaker.should_allow():
            return StageResult(
                status="error",
                error=f"Circuit breaker OPEN for {stage.name} (too many recent failures)")

        for attempt in range(max_retries + 1):
            try:
                result = await asyncio.wait_for(
                    stage.execute(ctx),
                    timeout=stage.timeout_seconds
                )
                breaker.record_success()
                return result
            except asyncio.TimeoutError:
                breaker.record_failure()
                if attempt == max_retries:
                    return StageResult(
                        status="timeout",
                        error=f"{stage.name} timed out after {stage.timeout_seconds}s")
                # Exponential backoff WITH jitter
                base_delay = 2 ** attempt
                jitter = random.uniform(0, base_delay * 0.5)
                await asyncio.sleep(base_delay + jitter)
            except Exception as e:
                breaker.record_failure()
                if attempt == max_retries:
                    return StageResult(status="error", error=str(e))
                base_delay = 2 ** attempt
                jitter = random.uniform(0, base_delay * 0.5)
                await asyncio.sleep(base_delay + jitter)
```

### 3.3 ThrottleController -- `app/scanner/throttle.py`

```python
import asyncio
from contextlib import asynccontextmanager

class ThrottleController:
    """
    Two-layer throttling: global cap + per-category cap.
    Every network operation MUST go through acquire().
    """
    def __init__(self):
        self.global_semaphore = asyncio.Semaphore(500)  # system-wide cap
        self.category_semaphores = {
            "dns":        asyncio.Semaphore(50),
            "tcp_scan":   asyncio.Semaphore(200),
            "tls_probe":  asyncio.Semaphore(10),
            "http_probe": asyncio.Semaphore(20),
            "path_fuzz":  asyncio.Semaphore(20),
            "crawl":      asyncio.Semaphore(5),
            "fuzz":       asyncio.Semaphore(3),
            "browser":    asyncio.Semaphore(2),
        }

    @asynccontextmanager
    async def acquire(self, category: str):
        """
        Acquire BOTH global and category semaphore.
        Usage: async with ctx.throttle.acquire("dns"): ...
        """
        cat_sem = self.category_semaphores.get(category, asyncio.Semaphore(10))
        async with self.global_semaphore:
            async with cat_sem:
                yield
```

### 3.4 Safe Scanning Policy (MANDATORY)

This section is non-negotiable. The scanner is powerful enough to disrupt services.

**Policy 1: Authorization.** Scans ONLY execute against domains explicitly provided in the scan request. The engine never follows out-of-scope redirects, never probes IPs not resolved from the target domain, never crawls external links.

**Policy 2: Scope enforcement.** Every HTTP request, DNS query, and TCP connection is checked against the authorized scope before execution:

```python
class ScopeGuard:
    """Enforced before every network operation."""
    def __init__(self, root_domain: str):
        self.root_domain = root_domain.lower()
        self.allowed_suffixes = [f".{self.root_domain}", self.root_domain]

    def is_in_scope(self, target: str) -> bool:
        target = target.lower().strip()
        # Hostname check
        if any(target.endswith(s) for s in self.allowed_suffixes):
            return True
        # IP check: only IPs resolved from in-scope hostnames
        return target in self._resolved_ips

    def add_resolved_ip(self, ip: str):
        self._resolved_ips.add(ip)
```

**Policy 3: Rate limits per target.** No single target host receives more than 20 requests/second. The AdaptiveRateController enforces this. If a host returns 429, scanning that host pauses for the duration indicated by `Retry-After` or 30 seconds.

**Policy 4: Scan depth gating.**

- `"fast"` -- No fuzzing, no brute-force, no browser. Read-only probes only.
- `"standard"` -- Path probing and header checks, but no parameter injection.
- `"aggressive"` -- Full fuzzing, browser DOM testing, exploit chain detection. Requires explicit `scan_depth: "aggressive"` in the request. This is the only mode that sends injection payloads.

**Policy 5: robots.txt.** By default, `robots.txt` is parsed and respected (disallowed paths are flagged as findings but not probed further). Override with `respect_robots: false` in scan options.

**Policy 6: No exploitation.** The scanner detects vulnerabilities; it does not exploit them. XSS validation uses a self-contained canary variable, not `alert()`. SQLi detection checks for error messages, not data exfiltration. SSTI checks for math evaluation, not command execution. No credentials are brute-forced. No sessions are hijacked.

### 3.5 Observability -- `app/scanner/observability.py`

Every scan produces structured metrics alongside findings.

```python
import time, json
from app.utils.logger import get_logger

logger = get_logger(__name__)

class ScanObserver:
    """Collects structured metrics throughout the pipeline."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.stage_metrics: list[StageMetrics] = []
        self.total_requests: int = 0
        self.total_errors: int = 0
        self.total_retries: int = 0
        self.start_time: float = time.time()

    def record_stage(self, metrics: StageMetrics):
        self.stage_metrics.append(metrics)
        self.total_requests += metrics.request_count
        if metrics.status in ("error", "timeout"):
            self.total_errors += 1
        # Structured JSON log
        logger.info(json.dumps({
            "event": "stage_complete",
            "scan_id": self.scan_id,
            "stage": metrics.name,
            "status": metrics.status,
            "duration_s": round(metrics.duration, 2),
            "requests": metrics.request_count,
            "error": metrics.error,
        }))

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "total_duration_s": round(time.time() - self.start_time, 2),
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "stages": [m.model_dump() for m in self.stage_metrics],
        }
```

### 3.6 Known Limitations (Documented)

**TCP connect scan limitations:**

- Cannot distinguish "filtered" from "silently dropped" reliably. A timeout may mean a firewall dropped the SYN, or the host is slow. Filtered ports are reported with LOW confidence.
- No SYN scan capability without raw sockets (requires root). The scanner uses full TCP handshake, which is slower and leaves connection logs on the target.
- Approximately 5-10x slower than SYN scanning for large port ranges.

**Cipher enumeration cost:**

- Testing N ciphers requires N separate TLS handshakes per host:port. For the full registry (~30 ciphers), this means ~30 connections per port. On a host with 5 TLS ports, that is 150 handshakes. The ThrottleController caps TLS probes at 10 concurrent to avoid overwhelming targets. This means cipher enumeration for 50 hosts can take 2-3 minutes.

**Browser engine dependency:**

- Playwright requires Chromium binary (~150MB download). If not installed, Stage 16 is skipped gracefully. The scanner works without it; SPA analysis and DOM XSS validation are simply unavailable.

**LLM dependency:**

- AI adaptive decisions require a running LM Studio instance. If unavailable, `chat_completion_safe` returns empty actions and the pipeline runs without AI guidance. No functionality is lost; only the adaptive intelligence layer is disabled.

---

## 4. Engine Designs -- All 12 Stages

### STAGE 1: Surface Recon Engine -- `engines/recon.py`

**Replaces:** `asset_discovery.py` (removes subfinder, amass, dnsx, httpx-toolkit subprocesses)

**Uses:** `dnspython` async resolver, `httpx` async client, raw TCP socket for WHOIS

**Step-by-step:**

1. **DNS record sweep** -- Query A, AAAA, MX, TXT, NS, SOA, CAA, SRV, CNAME for root domain via `dns.asyncresolver.Resolver`
2. **CT log mining** -- `GET https://crt.sh/?q=%.{domain}&output=json` via `httpx`, extract all `name_value` entries, deduplicate, strip wildcards
3. **Subdomain brute-force** -- Load `data/subdomain_wordlist.txt` (~500 entries), resolve `{word}.{domain}` via async DNS with semaphore(50)
4. **Merge + deduplicate** -- Union of CT results + brute-force results + any DNS-discovered subdomains (CNAME targets, MX hosts, NS hosts)
5. **DNS liveness check** -- For each candidate, resolve A record. Only survivors pass through.
6. **IP resolution** -- `gethostbyname` equivalent via `dns.asyncresolver` for each live subdomain, build `ip_map: dict[str, list[str]]`
7. **Reverse DNS** -- For each unique IP, query PTR record to find hostnames sharing the IP
8. **WHOIS lookup** -- Raw TCP to `whois.iana.org:43`, follow referral, parse with regex for registrar/dates/nameservers
9. **Zone transfer attempt** -- `dns.query.xfr()` against each NS. Flag if successful (misconfig).
10. **SPF/DMARC/DKIM** -- Parse TXT records for `v=spf1`, `_dmarc.{domain}` TXT, `{selector}._domainkey.{domain}` TXT

**Inputs:**

```python
class ReconInput(BaseModel):
    domain: str
    max_subdomains: int = 200
    enable_ct_logs: bool = True
    enable_whois: bool = True
    enable_brute_force: bool = True
    dns_timeout: float = 3.0
```

**Outputs:**

```python
class ReconResult(BaseModel):
    subdomains: list[str]
    ip_map: dict[str, list[str]]     # hostname -> [IPs]
    dns_records: list[DNSRecord]
    whois: Optional[WhoisInfo]
    ct_hosts: list[str]
    reverse_dns: dict[str, str]      # IP -> PTR hostname
    zone_transfer_vulnerable: bool
    spf_record: Optional[str]
    dmarc_record: Optional[str]
```

**Key implementation detail -- CT log query:**

```python
async def mine_ct_logs(domain: str, client: httpx.AsyncClient) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = await client.get(url, timeout=15.0)
    if resp.status_code != 200:
        return []
    hostnames = set()
    for entry in resp.json():
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}") or name == domain:
                hostnames.add(name.lower())
    return sorted(hostnames)
```

**Key implementation detail -- DNS brute-force:**

```python
async def brute_force_subdomains(
    domain: str, wordlist: list[str], sem: asyncio.Semaphore,
    resolver: dns.asyncresolver.Resolver
) -> list[str]:
    confirmed = []
    async def check(word):
        async with sem:
            fqdn = f"{word}.{domain}"
            try:
                await resolver.resolve(fqdn, "A")
                confirmed.append(fqdn)
            except Exception:
                pass
    await asyncio.gather(*[check(w) for w in wordlist])
    return confirmed
```

**Key implementation detail -- WHOIS:**

```python
async def query_whois(domain: str) -> WhoisInfo:
    reader, writer = await asyncio.open_connection("whois.iana.org", 43)
    writer.write(f"{domain}\r\n".encode())
    await writer.drain()
    raw = (await reader.read(4096)).decode(errors="replace")
    writer.close()
    # Follow referral
    refer = re.search(r"refer:\s+(\S+)", raw, re.IGNORECASE)
    if refer:
        reader2, writer2 = await asyncio.open_connection(refer.group(1), 43)
        writer2.write(f"{domain}\r\n".encode())
        await writer2.drain()
        raw = (await reader2.read(16384)).decode(errors="replace")
        writer2.close()
    return _parse_whois(raw)
```

---

### STAGE 2: Network Scan Engine -- `engines/network.py`

**Replaces:** `scan_ports()` in `asset_discovery.py` (removes nmap subprocess)

**Uses:** `asyncio.open_connection` (stdlib), raw socket reads for banners

**Step-by-step:**

1. **Async TCP connect scan** -- For each IP x port, call `asyncio.open_connection` with 2s timeout. Open = success, `ConnectionRefused` = closed, timeout = filtered. Semaphore(200) for parallelism.
2. **Banner grabbing** -- On each open port, reconnect and read up to 4096 bytes. For HTTP ports, send `GET / HTTP/1.0\r\nHost: {host}\r\n\r\n`. For SSH/SMTP/FTP/MySQL, the server sends a banner on connect. Redis gets `PING\r\n`.
3. **Service fingerprinting** -- Match banner bytes against `data/service_signatures.json` regex patterns. Extract service name + version string. Patterns: `SSH-2.0-OpenSSH_(\S+)`, `HTTP/1\.[01]`, `220 .+ESMTP`, `\+PONG` (Redis), etc.
4. **ASN/BGP lookup** -- For each unique IP, query `{reversed_octets}.origin.asn.cymru.com` TXT via dnspython. Parse pipe-separated fields: ASN, prefix, country, registry, org.
5. **Protocol classification** -- Assign each port a protocol category (http, https, ssh, smtp, ftp, db, rdp, unknown) from service name + port number.

**Port profiles:**

```python
PORT_PROFILES = {
    "web":     [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443],
    "banking": [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                1433, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 15672, 27017],
    "standard": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                 8080, 8443, 8888, 27017],
}
```

**Key implementation -- TCP scanner:**

```python
async def scan_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return PortResult(ip=ip, port=port, state="open")
    except asyncio.TimeoutError:
        return PortResult(ip=ip, port=port, state="filtered")
    except ConnectionRefusedError:
        return PortResult(ip=ip, port=port, state="closed")
    except OSError:
        return PortResult(ip=ip, port=port, state="error")
```

**Key implementation -- banner grabber:**

```python
BANNER_PROBES = {
    80:  b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443: None,   # TLS -- handled by Stage 4
    22:  b"",    # SSH sends banner on connect
    25:  b"",    # SMTP sends banner on connect
    21:  b"",    # FTP sends banner on connect
    3306: b"",   # MySQL sends handshake packet
    6379: b"PING\r\n",
}

async def grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        probe = BANNER_PROBES.get(port, b"")
        if probe:
            writer.write(probe.replace(b"{host}", ip.encode()))
            await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        writer.close()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
```

**Outputs:**

```python
class ServiceFingerprint(BaseModel):
    host: str
    port: int
    state: str                          # open | filtered | closed
    service_name: Optional[str] = None  # http, ssh, smtp, mysql, etc.
    product: Optional[str] = None       # OpenSSH, Apache, nginx, etc.
    version: Optional[str] = None       # 8.9p1, 2.4.52, etc.
    raw_banner: Optional[str] = None
    protocol_category: Optional[str] = None  # web, mail, db, remote, etc.
    confidence: str = "medium"

class ASNInfo(BaseModel):
    asn: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    org: Optional[str] = None
```

---

### STAGE 3: OS Fingerprint Engine -- `engines/os_fingerprint.py`

**Purpose:** Determine the OS, runtime, and deployment topology of each host from observable signals. Entirely passive -- no raw packet crafting needed.

**Uses:** Data already collected in Stages 1-2 (banners, headers, DNS), plus targeted HTTP probes

**Step-by-step:**

1. **SSH banner parsing** -- Regex on SSH banners: `OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` -> Ubuntu 22.04. `OpenSSH_8.0 FreeBSD-20230831` -> FreeBSD. Maintain a mapping table of SSH version -> OS release.
2. **HTTP Server header** -- `Server: Apache/2.4.52 (Ubuntu)` -> Ubuntu, `Server: Microsoft-IIS/10.0` -> Windows Server 2016+, `Server: nginx/1.18.0 (Ubuntu)` -> Ubuntu.
3. **X-Powered-By / Via** -- `X-Powered-By: PHP/8.1.2-1ubuntu2.14` -> Ubuntu, `X-Powered-By: Express` -> Node.js runtime.
4. **TTL analysis** -- Connect to port, read IP TTL from response. 64 = Linux/macOS, 128 = Windows, 255 = network device/Solaris. (Note: Python `socket` does not expose TTL directly in userspace; this is a best-effort probe via `asyncio.open_connection` and is LOW confidence.)
5. **Container indicators** -- Hostname patterns (`*-deployment-`*, hex-like hostnames), response header `X-Forwarded-For` behavior, Kubernetes-related headers.
6. **Vote aggregation** -- Each evidence source casts a weighted vote. The OS family with the highest total weight wins. Multiple agreeing sources boost confidence from LOW to MEDIUM to HIGH.

**Key data structures:**

```python
class OSFingerprint(BaseModel):
    host: str
    os_family: Optional[str] = None       # Linux, Windows, macOS, FreeBSD
    os_version: Optional[str] = None      # Ubuntu 22.04, Windows Server 2019
    os_confidence: str = "low"            # low | medium | high
    runtime: Optional[str] = None         # Node.js, Python, Java, PHP, .NET
    container_likely: bool = False
    container_evidence: list[str] = []
    evidence_sources: list[str] = []      # ["ssh_banner", "http_server", "ttl"]
```

**Evidence weight table:**

```python
OS_EVIDENCE_WEIGHTS = {
    "ssh_banner_exact": 0.9,    # "Ubuntu-3ubuntu0.1" is very specific
    "http_server_os":   0.7,    # "Apache/2.4.52 (Ubuntu)"
    "x_powered_by":     0.5,    # runtime, not OS directly
    "cookie_name":      0.3,    # PHPSESSID -> probably Linux
    "ttl_guess":        0.2,    # unreliable through NAT/CDN
    "hostname_pattern": 0.3,    # container hostname heuristic
}
```

---

### STAGE 4: TLS / Crypto Engine -- `engines/tls_engine.py`

**Replaces:** `tls_scanner.py` entirely (removes sslscan, testssl, zgrab2, openssl subprocesses)

**Uses:** Python `ssl` stdlib for handshakes, `cryptography` library for cert parsing

**Step-by-step:**

1. **TLS version probing** -- For each TLS version (1.0, 1.1, 1.2, 1.3), create an `ssl.SSLContext` with `minimum_version = maximum_version = target_version`. Attempt `asyncio.open_connection(host, port, ssl=ctx)`. Success = version supported.
2. **Cipher suite enumeration** -- For each cipher in `data/cipher_registry.json`, create an `ssl.SSLContext` with `ctx.set_ciphers(cipher_name)`. Attempt connection. Success = server accepts this cipher. Semaphore(10) to avoid overwhelming the target.
3. **Certificate chain extraction** -- Connect with permissive context (`verify_mode=CERT_NONE`), call `ssl_obj.getpeercert(binary_form=True)`, parse with `cryptography.x509.load_der_x509_certificate`. Extract: subject, issuer, SANs, validity dates, key type/size, signature algorithm, serial, SHA-256 fingerprint.
4. **OCSP stapling check** -- Inspect the TLS extension during handshake. Python's `ssl` module exposes this via `ssl_obj.getpeercert()` dict which includes OCSP response if stapled.
5. **STARTTLS support** -- For SMTP (25/587), IMAP (143), POP3 (110): open a plain TCP connection, read the greeting, send the protocol-specific STARTTLS command (`EHLO host\r\nSTARTTLS\r\n` for SMTP), then upgrade to TLS with `asyncio.open_connection` ssl wrap.
6. **PQC signal detection** -- Check negotiated cipher names and key exchange groups for PQC indicators: `X25519Kyber768`, `mlkem768`, `x25519_kyber512`. These appear in the TLS 1.3 key share extension.

**Inputs/Outputs:**

```python
class TLSProfile(BaseModel):
    host: str
    port: int
    tls_versions_supported: dict[str, bool]  # {"TLS_1_0": False, "TLS_1_2": True, ...}
    accepted_ciphers: list[CipherDetail]
    negotiated_cipher: Optional[str] = None
    cert_chain: list[CertificateDetail]
    leaf_cert: Optional[CertificateDetail] = None
    forward_secrecy: bool = False
    ocsp_stapling: Optional[bool] = None
    starttls_protocol: Optional[str] = None  # smtp, imap, pop3
    pqc_signals: list[str] = []
    confidence: str = "high"

class CipherDetail(BaseModel):
    name: str
    kex: str               # ECDHE, DHE, RSA, X25519Kyber768
    auth: str              # RSA, ECDSA
    encryption: str        # AES-256-GCM, AES-128-CBC, 3DES, RC4
    mac: str               # SHA384, SHA256, SHA1, MD5
    bits: Optional[int] = None
    pfs: bool = False
    pqc: bool = False
    strength: str = "unknown"  # strong | acceptable | weak | insecure

class CertificateDetail(BaseModel):
    subject: str
    issuer: str
    serial: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    expired: bool = False
    key_type: str            # RSA, EC, Ed25519
    key_size: int
    sig_algorithm: str
    sans: list[str] = []
    is_self_signed: bool = False
    fingerprint_sha256: str
    quantum_vulnerable: bool = True
```

**Key implementation -- TLS version probe:**

```python
async def probe_tls_version(host: str, port: int, version) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=5.0
        )
        writer.close()
        return True
    except (ssl.SSLError, asyncio.TimeoutError, OSError):
        return False
```

**Key implementation -- cert extraction:**

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

async def extract_cert(host: str, port: int) -> Optional[CertificateDetail]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _, writer = await asyncio.open_connection(
        host, port, ssl=ctx, server_hostname=host
    )
    ssl_obj = writer.get_extra_info("ssl_object")
    der = ssl_obj.getpeercert(binary_form=True)
    writer.close()
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    key_type = "RSA" if isinstance(pub, rsa.RSAPublicKey) else \
               "EC" if isinstance(pub, ec.EllipticCurvePublicKey) else "unknown"
    return CertificateDetail(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=str(cert.serial_number),
        valid_from=cert.not_valid_before_utc.isoformat(),
        valid_to=cert.not_valid_after_utc.isoformat(),
        days_until_expiry=(cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
        key_type=key_type,
        key_size=pub.key_size,
        sig_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        sans=_extract_sans(cert),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )
```

---

### STAGE 5: Crypto Analysis Engine -- `engines/crypto_analysis.py`

**Extends:** Existing `crypto_analyzer.py` logic, but now operates on richer `TLSProfile` data from Stage 4.

**Step-by-step:**

1. **Per-cipher classification** -- For each accepted cipher, classify its key exchange, encryption, and MAC against the NIST PQC risk map. Tag quantum_risk (none/low/medium/high/critical), HNDL risk (bool), and NIST recommendation.
2. **Certificate key classification** -- RSA/ECDSA keys are quantum-vulnerable (Shor's algorithm). Tag each cert key with quantum_risk and recommended PQC replacement.
3. **Protocol risk** -- SSLv2/3 = critical, TLS 1.0/1.1 = high, TLS 1.2 without PFS = medium, TLS 1.3 = low.
4. **HNDL assessment** -- Any host using classical key exchange (RSA, ECDHE without PQC hybrid) is HNDL-vulnerable. Flag with urgency based on asset criticality.
5. **PQC readiness** -- If any cipher or key exchange is PQC-hybrid (X25519Kyber768, mlkem768), mark host as PQC-ready.
6. **Aggregate per-host** -- Compute composite crypto score 0-100 for each host. Deductions are evidence-backed with specific cipher/protocol references.

**Outputs:**

```python
class CryptoFinding(BaseModel):
    host: str
    port: int
    component: str          # key_exchange, cipher, protocol, certificate
    algorithm: str
    quantum_risk: str       # none | low | medium | high | critical
    threat_vector: Optional[str] = None  # "Shor", "Grover", "Classical"
    hndl_risk: bool = False
    nist_recommendation: Optional[str] = None
    evidence: str
    confidence: str = "high"
```

---

### STAGE 6: CDN / WAF / Proxy Detection Engine -- `engines/cdn_waf.py`

**New module.** No external tools.

**Uses:** `httpx` async client, DNS CNAME inspection, response header analysis

**Step-by-step:**

1. **CDN detection via DNS CNAME** -- Resolve CNAME chain for each subdomain. Match terminal CNAME against known CDN patterns: `*.cloudfront.net` -> CloudFront, `*.cdn.cloudflare.net` -> Cloudflare, `*.akamaiedge.net` -> Akamai, `*.fastly.net` -> Fastly, `*.azureedge.net` -> Azure CDN.
2. **CDN detection via response headers** -- `cf-ray` -> Cloudflare, `x-amz-cf-id` -> CloudFront, `x-served-by` -> Fastly/Varnish, `x-cache` -> generic CDN, `x-cdn` header.
3. **WAF fingerprinting** -- Send a clean `GET /` and a suspicious `GET /?test=<script>alert(1)</script>`. Compare responses. If clean=200 and malicious=403/406/429, WAF is present. Then fingerprint: `cf-chl-bypass` header -> Cloudflare WAF, `x-amzn-waf-` headers -> AWS WAF, `AkamaiGHost` in Server -> Akamai, `ModSecurity` in 403 body.
4. **Reverse proxy detection** -- `Via` header presence, `X-Forwarded-For` reflection when sent, Server header mismatch (e.g., `Server: nginx` but response body shows `IIS` error page).
5. **Cloud provider by ASN** -- Match ASN (from Stage 2) against known cloud ASNs: AWS (AS16509, AS14618), Azure (AS8075), GCP (AS15169, AS396982), Cloudflare (AS13335).

**Outputs:**

```python
class InfrastructureIntel(BaseModel):
    host: str
    cdn_provider: Optional[str] = None
    cdn_evidence: list[str] = []
    waf_detected: bool = False
    waf_provider: Optional[str] = None
    waf_evidence: list[str] = []
    reverse_proxy: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_evidence: list[str] = []
    confidence: str = "medium"
```

---

### STAGE 7: Tech Fingerprint Engine -- `engines/tech_fingerprint.py`

**New module.** No external tools.

**Uses:** `httpx` for HTTP requests. All detection is regex/pattern matching against responses.

**Step-by-step:**

1. **HTTP response capture** -- `GET /` on each web-facing host. Store full headers + first 64KB of body.
2. **Header-based detection** -- Match `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `X-Drupal-Cache` against `data/tech_signatures.json`.
3. **HTML meta tags** -- `<meta name="generator" content="WordPress 6.4.2">`, `<meta name="framework">`.
4. **Script/link analysis** -- Scan `<script src="...">` and `<link href="...">` for known library paths: `/wp-content/` -> WordPress, `react.production.min.js` -> React, `angular.min.js` -> Angular, `jquery-X.Y.Z.min.js` -> jQuery version.
5. **Cookie name fingerprinting** -- `JSESSIONID` -> Java, `PHPSESSID` -> PHP, `ASP.NET_SessionId` -> .NET, `connect.sid` -> Express/Node, `laravel_session` -> Laravel.
6. **Favicon hash** -- Download `/favicon.ico`, compute MD5 hash, compare against known favicon hash database (Shodan-style). Example: default Tomcat favicon hash = `d41d8cd98f00b204e9800998ecf8427e`.
7. **Error page fingerprinting** -- Request a deliberately invalid path (`/qshield_404_probe_xyz`). Parse the 404 page for framework signatures: `Whitelabel Error Page` -> Spring Boot, `Django Version:` -> Django, etc.

**Outputs:**

```python
class TechFingerprint(BaseModel):
    host: str
    category: str        # web_server, language, framework, cms, js_lib, cdn, analytics
    name: str            # nginx, PHP, Laravel, WordPress, React, Cloudflare
    version: Optional[str] = None
    confidence: str      # low | medium | high
    evidence: str        # "Server: nginx/1.18.0" or "cookie PHPSESSID"
    cpe: Optional[str] = None  # CPE for CVE matching
```

**Signature format in `tech_signatures.json`:**

```json
[
  {
    "name": "WordPress",
    "category": "cms",
    "matches": [
      {"type": "html", "pattern": "/wp-content/", "confidence": "high"},
      {"type": "html", "pattern": "<meta name=\"generator\" content=\"WordPress ([\\d.]+)\"", "version_group": 1, "confidence": "high"},
      {"type": "cookie", "pattern": "wordpress_logged_in", "confidence": "medium"},
      {"type": "header", "pattern": "X-Pingback.*xmlrpc\\.php", "confidence": "high"}
    ],
    "cpe_template": "cpe:2.3:a:wordpress:wordpress:{version}"
  }
]
```

---

### STAGE 8: Web / API Discovery Engine -- `engines/web_discovery.py`

**Replaces/extends:** `headers_scanner.py` (which only does a single HEAD request)

**Uses:** `httpx` async client

**Step-by-step:**

1. **Security header audit** -- `GET /` on each web host. Check for: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`. Score each as present/correct/misconfigured/missing.
2. **Cookie analysis** -- Parse all `Set-Cookie` headers. Check each for: `Secure` flag, `HttpOnly` flag, `SameSite` attribute, `Path` scope, `__Host-`/`__Secure-` prefixes. Flag cookies missing security attributes.
3. **CORS audit** -- Send `GET /` with `Origin: https://evil.example.com`. Check `Access-Control-Allow-Origin` response. If it reflects the evil origin or is `*` with `Access-Control-Allow-Credentials: true`, flag as permissive CORS.
4. **API schema discovery** -- Probe: `/openapi.json`, `/swagger.json`, `/swagger/v1/swagger.json`, `/api-docs`, `/api/docs`, `/.well-known/openapi`, `/graphql` (POST introspection query `{"query":"{ __schema { types { name } } }"}`). If a schema is found, parse its paths to enumerate documented API endpoints.
5. **Well-known URIs** -- Probe: `/.well-known/security.txt`, `/.well-known/change-password`, `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`, `/.well-known/openid-configuration`.

**Outputs:**

```python
class WebAppProfile(BaseModel):
    host: str
    url: str
    status_code: int
    security_headers: dict[str, HeaderAuditResult]  # header_name -> {present, value, compliant, issue}
    header_score: float  # 0-100
    cookies: list[CookieAudit]
    cors: CORSAudit
    api_schemas_found: list[APISchemaResult]
    well_known_results: dict[str, WellKnownResult]
    info_leaks: list[str]  # e.g., "Server version disclosed", "X-Powered-By present"
```

---

### STAGE 9: Hidden Discovery Engine -- `engines/hidden_discovery.py`

**New module.** No external tools.

**Uses:** `httpx` async client, regex for JS parsing

**Step-by-step:**

1. **robots.txt parsing** -- `GET /robots.txt`. Extract all `Disallow:` and `Allow:` paths. Probe each for HTTP status.
2. **sitemap.xml parsing** -- `GET /sitemap.xml`. If sitemap index, follow child sitemaps. Extract all URL paths.
3. **Path brute-force** -- Load `data/common_paths.txt` (~300 high-value paths in 3 tiers: critical, high, medium). Probe each with `GET`. Use Semaphore(20) for rate control, 5s timeout per request.
4. **Backup file detection** -- For each discovered path that returned 200, also probe: `{path}.bak`, `{path}.old`, `{path}~`, `{path}.swp`, `{path}.orig`, `{path}.zip`.
5. **Admin panel detection** -- Dedicated probes: `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`, `/adminer.php`, `/console`, `/actuator`, `/actuator/env`, `/debug`.
6. **Sensitive file exposure** -- `/.env`, `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.DS_Store`, `/web.config`, `/config.php`, `/config.json`, `/database.yml`.
7. **JS route extraction** -- From the HTML of the main page, find all `<script src="...">` tags. Download each JS file (cap: 20 files). Regex-extract route patterns: `"/api/..."`, `path: "/..."`, `fetch("/..."`.
8. **Confidence scoring** -- Every finding gets a confidence score based on status code + content verification. A 200 on `/.git/HEAD` with body starting `ref: refs/heads/` = confidence 1.0. A 200 on `/admin` with a generic page = confidence 0.4. A 403 on `/admin` = confidence 0.5 (exists but blocked).

**Outputs:**

```python
class HiddenFinding(BaseModel):
    host: str
    path: str
    status_code: int
    discovery_source: str    # robots_txt | sitemap | brute_force | backup | admin | sensitive_file | js_extraction
    finding_type: str        # admin_panel | backup_file | config_exposure | git_exposure | api_leak | info_disclosure
    risk: str                # critical | high | medium | low
    confidence: float        # 0.0 - 1.0
    evidence: str            # "HTTP 200 on /.git/HEAD, body starts with 'ref: refs/heads/'"
```

**Key implementation -- confidence calculator:**

```python
def calculate_confidence(status: int, path: str, body: str) -> float:
    if status == 404:
        return 0.0
    base = {200: 0.7, 403: 0.5, 401: 0.6, 301: 0.4, 302: 0.3}.get(status, 0.1)
    # Content verification boosts
    if ".git/HEAD" in path and "ref: refs/heads/" in body:
        return 1.0
    if ".env" in path and any(k in body for k in ["DB_", "SECRET", "API_KEY", "PASSWORD"]):
        return 1.0
    if "swagger" in path.lower() and '"openapi"' in body.lower():
        return 0.95
    if "actuator" in path and '"status"' in body:
        return 0.85
    # Generic 404 page masquerading as 200
    if any(p in body.lower()[:500] for p in ["page not found", "404 error", "not found"]):
        return base * 0.2
    return base
```

---

### STAGE 10: Vulnerability Engine -- `engines/vuln_engine.py`

**Replaces:** `vuln_scanner.py` (removes Nuclei subprocess) and `cve_mapper.py` (replaces static lambdas)

**Uses:** Pure Python rule engine against collected data from all prior stages

**Step-by-step:**

1. **Rule-based vulnerability matching** -- Load `data/vuln_rules.json`. Each rule defines: `id`, `name`, `severity`, `condition` (a set of field checks against scan data), `evidence_template`, `remediation`. Rules cover: TLS misconfigurations, missing security headers, exposed admin panels, weak ciphers, expired certs, known default credentials ports, etc.
2. **CVE correlation** -- For each `TechFingerprint` with a CPE string and version, query a local `data/cve_cache.json` (periodically refreshed from NVD). Match `cpe` + version range. This replaces the 8 hardcoded lambdas in `cve_mapper.py`.
3. **Behavioral probes** -- Targeted checks: (a) send `X-Forwarded-For: 127.0.0.1` and see if response changes (proxy trust issue), (b) send different `User-Agent` values and compare responses (cloaking), (c) check for open redirect via `?redirect=https://evil.com`.
4. **Misconfig detection** -- CORS wildcard with credentials, directory listing enabled (HTML title `Index of /`), verbose error pages with stack traces, default credentials pages (Tomcat manager, Jenkins, etc.).
5. **Deduplication** -- Findings are deduped by `(host, vuln_id)` pair, keeping the highest-confidence instance.

**Outputs:**

```python
class VulnFinding(BaseModel):
    host: str
    vuln_id: str            # "QS-VULN-001" for custom rules, "CVE-2024-XXXX" for CVEs
    name: str
    severity: str           # critical | high | medium | low | info
    category: str           # tls_misconfig | missing_header | exposed_panel | cve | behavioral
    evidence: str
    confidence: float       # 0.0 - 1.0
    remediation: str
    cve_ids: list[str] = []
    affected_component: Optional[str] = None
    quantum_relevance: bool = False  # True if this vuln is quantum-related
```

**Example rule in `vuln_rules.json`:**

```json
{
  "id": "QS-VULN-TLS-001",
  "name": "TLS 1.0 Enabled",
  "severity": "high",
  "category": "tls_misconfig",
  "condition": {"tls_versions_supported.TLS_1_0": true},
  "evidence_template": "Host {host}:{port} accepts TLS 1.0 connections",
  "remediation": "Disable TLS 1.0. Require TLS 1.2 minimum, TLS 1.3 preferred.",
  "cve_ids": ["CVE-2011-3389", "CVE-2014-3566"],
  "quantum_relevance": true
}
```

---

### STAGE 11: Correlation + Risk Scoring Engine -- `engines/correlation.py`

**New module.** Merges two responsibilities: graph construction and risk scoring.

**Step-by-step (correlation):**

1. **Node creation** -- One node per: domain, subdomain, IP, service (host:port), certificate (by fingerprint), technology, ASN, finding.
2. **Edge creation** -- domain->subdomain (has_subdomain), subdomain->IP (resolves_to), IP->ASN (belongs_to), host:port->service (runs), host->certificate (presents), technology->host (detected_on), finding->host (affects), finding->CVE (maps_to).
3. **Shared infrastructure** -- Group hosts by shared IP, shared cert fingerprint, shared ASN. Tag as "co-hosted" or "same-origin".
4. **Attack path derivation** -- BFS from root domain node to all finding/threat nodes. Each path is scored: `product(edge_weights)`. Shorter paths with critical findings rank highest.

**Step-by-step (risk scoring):**

1. **Per-asset composite score** -- Weighted sum across 7 dimensions:

- Crypto posture (weight 0.20): TLS version penalties, weak cipher count, PFS, PQC readiness, cert validity
- Network exposure (weight 0.15): count of open high-risk ports (DB, RDP, admin), total open ports
- OS/software age (weight 0.15): EOL software, outdated versions from tech fingerprints
- Web security (weight 0.15): header score, cookie issues, CORS issues, info leaks
- Attack surface (weight 0.15): hidden paths found, exposed APIs, admin panels
- Infrastructure (weight 0.10): WAF bonus, CDN bonus, direct IP penalty
- CVE exposure (weight 0.10): weighted sum of CVE severities (critical=10, high=7, medium=4, low=1)

1. **Estate-wide score** -- Aggregate per-asset scores using bottom-quartile weighting (worst assets pull the average down more). Hard ceiling: cannot be "Elite" if any asset is "Critical".
2. **Tier classification** -- Score 0-1000: Critical (0-200), Legacy (201-400), Standard (401-700), Elite-PQC (701-1000).
3. **Scan diff** -- Compare current scan results against most recent completed scan for the same domain. Compute: new_assets, removed_assets, new_ports, closed_ports, new_findings, resolved_findings, score_delta.

**Outputs:**

```python
class AssetRiskScore(BaseModel):
    host: str
    overall_score: float          # 0-100
    risk_level: str               # critical | high | medium | low | safe
    dimension_scores: dict[str, float]
    top_risk_drivers: list[RiskDriver]
    remediation_priority: int     # 1 = fix first

class GraphNode(BaseModel):
    id: str
    node_type: str
    label: str
    properties: dict = {}

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    weight: float = 1.0

class AssetGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]

class ScanDiff(BaseModel):
    new_assets: list[str]
    removed_assets: list[str]
    new_findings: list[str]
    resolved_findings: list[str]
    score_delta: float
```

---

### STAGE 12: CBOM + Report Engine -- `engines/reporting.py`

**Extends:** Existing `cbom_generator.py` + `recommendation_engine.py` + `report_bundle.py`

**Step-by-step:**

1. **CBOM construction** -- Build CERT-IN Annexure-A compliant CBOM from all crypto components: certificates (subject, issuer, validity, key type/size, sig algorithm, serial), protocols (TLS versions with cipher suites), algorithms (key exchange, encryption, MAC with OIDs and quantum classification). Deduplicate by `(host, name, category)`.
2. **Prioritized recommendations** -- Generate recommendations from all findings, sorted by: severity (critical first), quantum_risk_reduction (highest first), effort (lowest first). Each recommendation includes NIST reference, specific action, affected hosts.
3. **Executive summary** -- Auto-generated text: total assets, overall score/tier, top 3 critical findings, HNDL exposure count, PQC readiness percentage, key recommendations.
4. **Export bundles** -- JSON (full data), CSV (flat asset table), Markdown (human-readable report). All existing export endpoints in `routes.py` are updated to use the new richer data.

### Engine-Level Operational Refinements

These per-engine constraints are applied during implementation:

**Recon Engine:**

- CT log responses from crt.sh are cached in MongoDB (`ct_cache` collection, keyed by domain, TTL 24 hours). Repeated scans of the same domain within 24h reuse the cached CT data.
- DNS queries use retry logic: up to 2 retries per record type with 1s delay. Different upstream resolvers are tried on failure (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9).

**Network Engine:**

- Ports are scanned in batches of 50 per host (not all at once). If the first 50 ports yield >40 closed, reduce the remaining batch to top-20 critical ports only (adaptive port scanning).
- All banner data is truncated to 4096 bytes before storing.

**TLS Engine:**

- Cipher enumeration is capped at 30 ciphers per host:port. If the server accepts the first 15 out of 15 probed, the remaining are probed. If it rejects all first 10, skip the rest (adaptive cipher probing).
- Max 5 concurrent TLS handshakes per single target host to avoid triggering rate limits.

**Vulnerability Engine:**

- Each rule evaluation has a 5-second timeout. Rules that exceed this are killed and logged.
- Rule execution is sandboxed: rules can only read scan context, not modify it or make network calls.

**Hidden Discovery Engine:**

- If >5 consecutive 429 responses are received from a host, stop brute-forcing that host immediately.
- If WAF was detected in Stage 6 for a host, reduce hidden path wordlist to "critical" tier only (fewer probes, less chance of triggering WAF blocks).

---

## 5. Complete Output Intelligence Model

### Per-Asset Schema -- `AssetIntelligence`

Every discovered asset carries the full profile:

```python
class AssetIntelligence(BaseModel):
    # Identity
    hostname: str
    ip_addresses: list[str]
    reverse_dns: list[str] = []
    asn: Optional[ASNInfo] = None

    # Network
    open_ports: list[int]
    services: list[ServiceFingerprint]

    # OS / Platform
    os_fingerprint: Optional[OSFingerprint] = None

    # Crypto
    tls_profiles: list[TLSProfile] = []
    crypto_findings: list[CryptoFinding] = []

    # Tech stack
    technologies: list[TechFingerprint] = []

    # Infrastructure
    infrastructure: Optional[InfrastructureIntel] = None

    # Web / API surface
    web_profile: Optional[WebAppProfile] = None

    # Hidden findings
    hidden_findings: list[HiddenFinding] = []

    # Vulnerabilities
    vuln_findings: list[VulnFinding] = []

    # Risk
    risk_score: Optional[AssetRiskScore] = None

    # Evidence trail
    evidence_sources: list[str] = []
    overall_confidence: str = "medium"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
```

### Scan-Level Schema -- `ScanIntelligenceReport`

The top-level output of a complete scan:

```python
class ScanIntelligenceReport(BaseModel):
    # Metadata
    scan_id: str
    domain: str
    started_at: str
    completed_at: str
    scanner_version: str
    scan_config: dict

    # Assets (each carries full intelligence)
    assets: list[AssetIntelligence]

    # Estate-wide scores
    quantum_score: dict         # score, tier, deductions, bonuses
    estate_risk_score: float
    estate_risk_level: str
    estate_tier: str            # Critical | Legacy | Standard | Elite-PQC

    # Asset graph
    asset_graph: AssetGraph

    # DNS intelligence
    dns_records: list[DNSRecord]
    whois: Optional[WhoisInfo] = None
    ct_entries: list[str] = []

    # CBOM
    cbom: dict                  # CERT-IN compliant CBOM

    # Prioritized findings
    all_findings: list[dict]    # sorted by severity * confidence
    top_findings: list[dict]    # top 10

    # Recommendations
    recommendations: list[dict]

    # Scan diff (if previous scan exists)
    diff: Optional[ScanDiff] = None

    # Summaries
    executive_summary: str
    technical_summary: str

    # Stats
    total_assets: int
    total_ports: int
    total_services: int
    total_findings: int
    scan_duration_seconds: float
```

---

## 6. Elite Layer -- Closing the Gaps

The base 12-stage design reaches ~70% of Nmap, ~60% of Nessus, ~50% of Burp. The following three engines push the system into elite territory. They are new stages 13-15, executed after Stage 12 when the user selects `scan_depth: "aggressive"` or when adaptive logic triggers them automatically.

### 6.1 GAP 1 FIX: Advanced Fingerprinting Engine -- `engines/advanced_fingerprint.py`

**Problem:** OS detection is banner-only (medium confidence max). No TCP/IP stack fingerprinting.

**Reality check:** True Nmap-style OS fingerprinting requires raw sockets (`SOCK_RAW`) and root/admin privileges to craft SYN probes with specific TCP options and read the raw SYN-ACK response. Python can do this via the `socket` module, but it requires elevated privileges and is blocked on many cloud hosts. The design below has two tiers: userspace (always runs) and privileged (runs only when available).

**Tier 1: Userspace fingerprinting (no root needed)**

These techniques work with normal `asyncio.open_connection` and give MEDIUM confidence:

1. **TCP window size analysis** -- Connect to an open port, read the TCP window size from the connection metadata. Different OS families use different default window sizes: Linux ~29200 or 65535, Windows ~65535 with specific scaling, FreeBSD ~65535. Python `socket.getsockopt(socket.SOL_TCP, socket.TCP_INFO)` on Linux exposes `tcpi_rcv_wscale` and `tcpi_snd_wscale`.
2. **TCP timestamp delta analysis** -- Make two connections 5 seconds apart. Read the TCP timestamp option (if exposed). Calculate the timestamp increment rate. Linux increments at ~1000/sec, Windows at ~100/sec, FreeBSD at ~1000/sec. Different rates disambiguate OS families.
3. **MSS (Maximum Segment Size) analysis** -- The MSS value advertised by the server during TCP handshake is OS-dependent. Linux default: 1460, Windows: 1460 but with specific TCP options pattern, Solaris: 1024. Read via `socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)`.
4. **Connection behavior analysis** -- Measure: time-to-first-byte after connection, RST behavior on closed ports (immediate vs delayed), FIN handling (graceful vs RST). Each OS handles these differently.
5. **Multi-probe correlation** -- Run probes against 3+ ports on the same host. If all SSH, HTTP, and SMTP banners agree on "Ubuntu", confidence goes to HIGH. If banners disagree, flag as "mixed signals" (possible container or proxy).

**Tier 2: Privileged fingerprinting (root/admin only, graceful skip otherwise)**

```python
import socket
import struct

async def raw_syn_probe(ip: str, port: int) -> Optional[TCPFingerprint]:
    """
    Send a crafted SYN with specific TCP options and analyze the SYN-ACK.
    Requires SOCK_RAW. Returns None if not permitted.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        return None  # graceful skip -- not root

    # Build TCP SYN with diagnostic options:
    # Window=65535, MSS=1460, WScale=10, SackOK, Timestamp, NOP padding
    tcp_options = build_diagnostic_options()
    syn_packet = build_syn_packet(ip, port, options=tcp_options)
    sock.sendto(syn_packet, (ip, 0))

    # Read SYN-ACK response
    response = await asyncio.wait_for(
        asyncio.get_event_loop().sock_recv(sock, 4096), timeout=3.0
    )
    sock.close()

    # Parse response TCP header
    return TCPFingerprint(
        window_size=parse_window(response),
        ttl=parse_ttl(response),
        df_bit=parse_df(response),
        mss=parse_mss(response),
        window_scale=parse_wscale(response),
        sack_ok=parse_sack(response),
        timestamp_present=parse_timestamp(response),
        options_order=parse_options_order(response),
    )
```

**OS matching database:**

```python
OS_FINGERPRINT_DB = [
    {
        "os": "Linux 5.x/6.x",
        "signatures": {
            "window_size": [65535, 29200, 64240],
            "ttl_range": [60, 64],
            "df_bit": True,
            "mss": [1460, 1448],
            "window_scale_range": [7, 10],
            "sack_ok": True,
            "timestamp_present": True,
            "options_order": "mss,sack,ts,nop,wscale",
        }
    },
    {
        "os": "Windows 10/11/Server 2019+",
        "signatures": {
            "window_size": [65535, 64240],
            "ttl_range": [125, 128],
            "df_bit": True,
            "mss": [1460],
            "window_scale_range": [8, 8],
            "sack_ok": True,
            "timestamp_present": False,
            "options_order": "mss,nop,wscale,nop,nop,sack",
        }
    },
    {
        "os": "FreeBSD 13+",
        "signatures": {
            "window_size": [65535],
            "ttl_range": [60, 64],
            "df_bit": True,
            "mss": [1460],
            "window_scale_range": [6, 7],
            "sack_ok": True,
            "timestamp_present": True,
            "options_order": "mss,nop,wscale,sack,ts",
        }
    },
]

def match_os(fp: TCPFingerprint) -> tuple[str, float]:
    """Match fingerprint against DB. Return (os_name, confidence 0.0-1.0)."""
    best_match, best_score = "unknown", 0.0
    for entry in OS_FINGERPRINT_DB:
        score = 0.0
        sigs = entry["signatures"]
        if fp.ttl in range(sigs["ttl_range"][0], sigs["ttl_range"][1] + 1):
            score += 0.25
        if fp.window_size in sigs["window_size"]:
            score += 0.20
        if fp.df_bit == sigs["df_bit"]:
            score += 0.10
        if fp.mss in sigs["mss"]:
            score += 0.15
        if fp.timestamp_present == sigs["timestamp_present"]:
            score += 0.15
        if fp.options_order == sigs["options_order"]:
            score += 0.15
        if score > best_score:
            best_score, best_match = score, entry["os"]
    return best_match, best_score
```

**Output model:**

```python
class AdvancedOSFingerprint(BaseModel):
    host: str
    tier: str                         # "userspace" | "privileged"
    os_match: str                     # "Linux 5.x/6.x", "Windows 10/11", etc.
    match_confidence: float           # 0.0 - 1.0
    tcp_window_size: Optional[int] = None
    ttl_observed: Optional[int] = None
    mss_observed: Optional[int] = None
    df_bit: Optional[bool] = None
    window_scale: Optional[int] = None
    timestamp_present: Optional[bool] = None
    options_order: Optional[str] = None
    evidence_sources: list[str] = []
```

---

### 6.2 GAP 2+4 FIX: Deep Crawl + Attacker Simulation Engine -- `engines/attack_surface.py`

**Problem:** Current design is stateless (single requests). No recursive crawling, no session handling, no login flow analysis, no injection testing, no exploit chaining.

**Scope constraint:** This is authorized scanning within approved scope. The engine simulates attacker reconnaissance techniques, not exploitation. It finds weaknesses; it does not weaponize them.

**Architecture:** The engine has 4 sub-components that run sequentially on each web-facing host.

#### Sub-component A: Stateful Crawler

```python
class StatefulCrawler:
    """
    Recursive web crawler that maintains session state (cookies, CSRF tokens).
    Extracts links, forms, and parameters from each page.
    Respects scope (same-domain only) and depth limits.
    """

    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set[str] = set()
        self.session_cookies: dict = {}
        self.discovered_forms: list[FormData] = []
        self.discovered_params: list[ParamData] = []
        self.discovered_links: list[str] = []

    async def crawl(self, client: httpx.AsyncClient) -> CrawlResult:
        queue: list[tuple[str, int]] = [(self.base_url, 0)]

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            try:
                resp = await client.get(url, follow_redirects=True, timeout=10.0)
                self._update_cookies(resp)
                html = resp.text

                # Extract links
                links = self._extract_links(html, url)
                for link in links:
                    if self._in_scope(link) and link not in self.visited:
                        queue.append((link, depth + 1))

                # Extract forms + parameters
                self._extract_forms(html, url)
                self._extract_url_params(url)

                # Extract inline JS API calls
                self._extract_js_endpoints(html)

            except Exception:
                continue

        return CrawlResult(
            pages_visited=len(self.visited),
            forms=self.discovered_forms,
            params=self.discovered_params,
            links=list(self.visited),
        )

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract href and src attributes, resolve relative URLs."""
        raw = re.findall(r'(?:href|src|action)=["\']([^"\'#]+)', html)
        resolved = []
        for link in raw:
            if link.startswith("http"):
                resolved.append(link)
            elif link.startswith("/"):
                resolved.append(f"{self._origin(base_url)}{link}")
            elif not link.startswith(("javascript:", "mailto:", "data:", "#")):
                resolved.append(f"{base_url.rsplit('/', 1)[0]}/{link}")
        return resolved

    def _extract_forms(self, html: str, page_url: str):
        """Extract <form> elements with their action, method, and input fields."""
        form_blocks = re.findall(
            r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
        )
        for i, block in enumerate(form_blocks):
            action = re.search(r'action=["\']([^"\']*)', block)
            method = re.search(r'method=["\']([^"\']*)', block, re.IGNORECASE)
            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']*)',
                block, re.IGNORECASE
            )
            self.discovered_forms.append(FormData(
                page_url=page_url,
                action=action.group(1) if action else page_url,
                method=(method.group(1) if method else "GET").upper(),
                fields=[{"name": n, "type": t} for n, t in inputs],
            ))

    def _in_scope(self, url: str) -> bool:
        """Only follow links within the same registered domain."""
        from urllib.parse import urlparse
        base_host = urlparse(self.base_url).hostname or ""
        link_host = urlparse(url).hostname or ""
        # Same domain or subdomain
        return link_host == base_host or link_host.endswith(f".{base_host}")
```

#### Sub-component B: Parameter Fuzzer

```python
class ParameterFuzzer:
    """
    For each discovered form and URL parameter, inject test payloads
    and observe response changes. Detects reflection, error disclosure,
    and behavioral anomalies.
    """

    FUZZ_PAYLOADS = {
        "xss_probe":     "<qshield>",
        "sqli_probe":    "' OR '1'='1",
        "ssti_probe":    "{{7*7}}",
        "path_traverse":  "../../etc/passwd",
        "open_redirect":  "https://evil.example.com",
        "cmd_injection":  "; echo qshield",
        "header_inject":  "qshield\r\nX-Injected: true",
    }

    async def fuzz_params(
        self, client: httpx.AsyncClient, params: list[ParamData],
        forms: list[FormData], sem: asyncio.Semaphore
    ) -> list[FuzzFinding]:
        findings = []

        # Phase 1: Get baseline responses for each form/param
        # Phase 2: Inject each payload, compare against baseline

        for param in params:
            baseline = await self._get_baseline(client, param, sem)
            for payload_name, payload_value in self.FUZZ_PAYLOADS.items():
                async with sem:
                    result = await self._inject_and_compare(
                        client, param, payload_name, payload_value, baseline
                    )
                    if result:
                        findings.append(result)

        for form in forms:
            baseline = await self._get_form_baseline(client, form, sem)
            for field in form.fields:
                for payload_name, payload_value in self.FUZZ_PAYLOADS.items():
                    async with sem:
                        result = await self._fuzz_form_field(
                            client, form, field, payload_name,
                            payload_value, baseline
                        )
                        if result:
                            findings.append(result)

        return findings

    async def _inject_and_compare(
        self, client, param, payload_name, payload_value, baseline
    ) -> Optional[FuzzFinding]:
        """Inject payload into param, compare response to baseline."""
        url = param.url.replace(
            f"{param.name}={param.original_value}",
            f"{param.name}={payload_value}"
        )
        try:
            resp = await client.get(url, follow_redirects=False, timeout=5.0)
            body = resp.text

            # Detection: reflected payload
            if payload_value in body and payload_value not in baseline.body:
                return FuzzFinding(
                    host=param.host, url=url, parameter=param.name,
                    payload_type=payload_name, payload=payload_value,
                    detection="reflected",
                    evidence=f"Payload '{payload_value}' reflected in response body",
                    severity=self._severity_for(payload_name, "reflected"),
                    confidence=0.85,
                )

            # Detection: error disclosure triggered
            error_sigs = ["Traceback", "SQL syntax", "mysql_", "ORA-", "SQLSTATE",
                         "stack trace", "Exception in", "Fatal error", "Parse error"]
            for sig in error_sigs:
                if sig in body and sig not in baseline.body:
                    return FuzzFinding(
                        host=param.host, url=url, parameter=param.name,
                        payload_type=payload_name, payload=payload_value,
                        detection="error_triggered",
                        evidence=f"Error signature '{sig}' appeared after injection",
                        severity="high",
                        confidence=0.80,
                    )

            # Detection: SSTI math evaluation
            if payload_name == "ssti_probe" and "49" in body and "49" not in baseline.body:
                return FuzzFinding(
                    host=param.host, url=url, parameter=param.name,
                    payload_type="ssti", payload=payload_value,
                    detection="ssti_evaluated",
                    evidence="Template expression {{7*7}} evaluated to 49",
                    severity="critical",
                    confidence=0.95,
                )

            # Detection: open redirect
            if payload_name == "open_redirect" and resp.status_code in [301, 302]:
                location = resp.headers.get("location", "")
                if "evil.example.com" in location:
                    return FuzzFinding(
                        host=param.host, url=url, parameter=param.name,
                        payload_type="open_redirect", payload=payload_value,
                        detection="redirect_to_external",
                        evidence=f"Redirect to {location}",
                        severity="medium",
                        confidence=0.90,
                    )

            # Detection: significant behavioral change (status code delta)
            if abs(resp.status_code - baseline.status) >= 100:
                return FuzzFinding(
                    host=param.host, url=url, parameter=param.name,
                    payload_type=payload_name, payload=payload_value,
                    detection="status_change",
                    evidence=f"Status changed from {baseline.status} to {resp.status_code}",
                    severity="medium",
                    confidence=0.50,
                )

        except Exception:
            pass
        return None
```

#### Sub-component C: GraphQL Deep Tester

```python
class GraphQLTester:
    """
    If GraphQL endpoint was found in Stage 8, probe it deeply:
    - Full introspection (types, fields, mutations)
    - Authorization bypass attempts (query without auth)
    - Excessive depth query (nested query DoS indicator)
    - Batching abuse (multiple operations in one request)
    """

    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind }
            args { name type { name } }
          }
        }
      }
    }
    """

    DEPTH_BOMB = """
    { user { friends { friends { friends { friends { friends { id } } } } } } }
    """

    async def test(self, client: httpx.AsyncClient, endpoint: str) -> list[GraphQLFinding]:
        findings = []

        # Test 1: Full introspection enabled?
        resp = await client.post(
            endpoint,
            json={"query": self.INTROSPECTION_QUERY},
            timeout=10.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data.get("data", {}):
                types = data["data"]["__schema"].get("types", [])
                mutations = data["data"]["__schema"].get("mutationType")
                findings.append(GraphQLFinding(
                    endpoint=endpoint,
                    finding="introspection_enabled",
                    severity="high",
                    evidence=f"Full schema exposed: {len(types)} types, mutations={'yes' if mutations else 'no'}",
                    confidence=1.0,
                    schema_types=[t["name"] for t in types if not t["name"].startswith("__")],
                ))

        # Test 2: Depth limit check
        try:
            resp = await client.post(
                endpoint,
                json={"query": self.DEPTH_BOMB},
                timeout=5.0
            )
            if resp.status_code == 200 and "errors" not in resp.json():
                findings.append(GraphQLFinding(
                    endpoint=endpoint,
                    finding="no_depth_limit",
                    severity="medium",
                    evidence="Deeply nested query accepted without error",
                    confidence=0.75,
                ))
        except Exception:
            pass

        # Test 3: Batch query abuse
        try:
            batch = [{"query": "{ __typename }"} for _ in range(20)]
            resp = await client.post(endpoint, json=batch, timeout=5.0)
            if resp.status_code == 200:
                findings.append(GraphQLFinding(
                    endpoint=endpoint,
                    finding="batch_queries_allowed",
                    severity="low",
                    evidence="Server accepted batch of 20 queries in single request",
                    confidence=0.70,
                ))
        except Exception:
            pass

        return findings
```

#### Sub-component D: Exploit Chain Detector

```python
class ExploitChainDetector:
    """
    Takes all findings from previous stages and the crawler, then detects
    multi-step exploit chains -- combinations of weaknesses that together
    create a higher-severity attack path.
    """

    CHAIN_PATTERNS = [
        {
            "id": "CHAIN-001",
            "name": "Exposed Admin + Weak Auth",
            "description": "Admin panel found with no WAF and weak TLS",
            "conditions": [
                {"type": "hidden_finding", "finding_type": "admin_panel", "min_confidence": 0.5},
                {"type": "infrastructure", "waf_detected": False},
            ],
            "severity": "critical",
            "attack_narrative": (
                "An attacker can directly access the admin panel at {path}. "
                "No WAF is protecting this endpoint. If default or weak credentials "
                "are in use, full application compromise is possible."
            ),
        },
        {
            "id": "CHAIN-002",
            "name": "HNDL + Sensitive API",
            "description": "API handling sensitive data uses quantum-vulnerable key exchange",
            "conditions": [
                {"type": "crypto_finding", "hndl_risk": True},
                {"type": "web_profile", "api_schemas_found_min": 1},
            ],
            "severity": "critical",
            "attack_narrative": (
                "This host exposes API endpoints and uses classical key exchange ({algorithm}). "
                "A state-level adversary collecting encrypted API traffic today can decrypt it "
                "when CRQC matures (~2030-2035). All transmitted data is at HNDL risk."
            ),
        },
        {
            "id": "CHAIN-003",
            "name": "Git Exposure + Config Leak",
            "description": ".git repository exposed, potentially leaking credentials",
            "conditions": [
                {"type": "hidden_finding", "finding_type": "git_exposure", "min_confidence": 0.9},
            ],
            "severity": "critical",
            "attack_narrative": (
                "The .git directory is publicly accessible at {path}. An attacker can "
                "reconstruct the full source code, extract hardcoded credentials, API keys, "
                "and database connection strings from commit history."
            ),
        },
        {
            "id": "CHAIN-004",
            "name": "Outdated CMS + Known CVE",
            "description": "CMS with known version has matching CVEs",
            "conditions": [
                {"type": "tech_fingerprint", "category": "cms", "has_version": True},
                {"type": "vuln_finding", "category": "cve", "severity_min": "high"},
            ],
            "severity": "critical",
            "attack_narrative": (
                "{tech_name} version {version} is running on {host}. "
                "CVE {cve_id} affects this version with severity {cve_severity}. "
                "Public exploits may be available."
            ),
        },
        {
            "id": "CHAIN-005",
            "name": "XSS + Session Cookie Without HttpOnly",
            "description": "Reflected XSS possible and session cookies are stealable",
            "conditions": [
                {"type": "fuzz_finding", "payload_type": "xss_probe", "detection": "reflected"},
                {"type": "cookie_audit", "http_only": False, "name_pattern": "session|sid|token"},
            ],
            "severity": "critical",
            "attack_narrative": (
                "Parameter {parameter} on {url} reflects user input without sanitization. "
                "The session cookie '{cookie_name}' lacks the HttpOnly flag. An attacker can "
                "chain these to steal user sessions via crafted XSS payload."
            ),
        },
        {
            "id": "CHAIN-006",
            "name": "Open Redirect + OAuth Flow",
            "description": "Open redirect can hijack OAuth authorization codes",
            "conditions": [
                {"type": "fuzz_finding", "payload_type": "open_redirect"},
                {"type": "well_known", "path": "/.well-known/openid-configuration", "found": True},
            ],
            "severity": "high",
            "attack_narrative": (
                "Open redirect at {url} combined with OpenID Connect configuration "
                "means an attacker can redirect OAuth callbacks to capture authorization codes."
            ),
        },
    ]

    def detect_chains(self, scan_context) -> list[ExploitChain]:
        chains = []
        for pattern in self.CHAIN_PATTERNS:
            matches = self._evaluate_conditions(pattern["conditions"], scan_context)
            if matches:
                chain = ExploitChain(
                    chain_id=pattern["id"],
                    name=pattern["name"],
                    severity=pattern["severity"],
                    description=pattern["description"],
                    narrative=self._fill_narrative(pattern["attack_narrative"], matches),
                    steps=[m["evidence"] for m in matches],
                    affected_hosts=list(set(m.get("host", "") for m in matches)),
                    confidence=min(m.get("confidence", 0.5) for m in matches),
                    remediation=self._chain_remediation(pattern["id"]),
                )
                chains.append(chain)
        return sorted(chains, key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}[c.severity])
```

**Output models for the entire attack surface engine:**

```python
class CrawlResult(BaseModel):
    pages_visited: int
    forms: list[FormData]
    params: list[ParamData]
    links: list[str]

class FormData(BaseModel):
    page_url: str
    action: str
    method: str
    fields: list[dict]

class ParamData(BaseModel):
    host: str
    url: str
    name: str
    original_value: str

class FuzzFinding(BaseModel):
    host: str
    url: str
    parameter: str
    payload_type: str
    payload: str
    detection: str        # reflected | error_triggered | ssti_evaluated | redirect_to_external | status_change
    evidence: str
    severity: str
    confidence: float

class GraphQLFinding(BaseModel):
    endpoint: str
    finding: str
    severity: str
    evidence: str
    confidence: float
    schema_types: list[str] = []

class ExploitChain(BaseModel):
    chain_id: str
    name: str
    severity: str
    description: str
    narrative: str        # filled-in attack story with actual host/path/CVE data
    steps: list[str]
    affected_hosts: list[str]
    confidence: float
    remediation: str
```

---

### 6.3 GAP 5+6 FIX: Adaptive Rate Controller + Behavioral Analysis -- `engines/adaptive.py`

**Problem:** Current ThrottleController uses fixed semaphores. No detection of blocking, no backoff on WAF triggers, no timing analysis, no response variance detection.

**Replaces:** The basic `ThrottleController` from Section 3.3.

#### Adaptive Rate Controller

```python
class AdaptiveRateController:
    """
    Monitors response patterns in real-time and adjusts scanning speed.
    Detects: rate limiting, WAF blocking, connection throttling, IP bans.
    Responds: backs off, rotates timing, reduces concurrency.
    """

    def __init__(self):
        self.semaphores: dict[str, asyncio.Semaphore] = {
            "dns": asyncio.Semaphore(50),
            "tcp_scan": asyncio.Semaphore(200),
            "tls_probe": asyncio.Semaphore(10),
            "http_probe": asyncio.Semaphore(20),
            "path_fuzz": asyncio.Semaphore(20),
            "crawl": asyncio.Semaphore(5),
            "fuzz": asyncio.Semaphore(3),
        }
        # Tracking state per target host
        self.host_state: dict[str, HostRateState] = {}
        self.global_backoff: float = 0.0

    def get(self, category: str) -> asyncio.Semaphore:
        return self.semaphores.get(category, asyncio.Semaphore(10))

    async def record_response(self, host: str, status: int, response_time: float):
        """Called after every HTTP request. Updates rate adaptation state."""
        state = self.host_state.setdefault(host, HostRateState())
        state.total_requests += 1
        state.response_times.append(response_time)

        # Detect rate limiting (429)
        if status == 429:
            state.rate_limit_hits += 1
            state.current_delay = min(state.current_delay * 2, 30.0)  # double delay, cap 30s
            state.concurrency_reduction += 1
            await self._reduce_concurrency("http_probe", factor=0.5)

        # Detect WAF blocking (403 spike)
        if status == 403:
            state.waf_blocks += 1
            if state.waf_blocks > 3 and state.waf_blocks / max(state.total_requests, 1) > 0.3:
                state.current_delay = min(state.current_delay + 2.0, 20.0)
                state.waf_triggered = True

        # Detect connection drops (0 status / timeout)
        if status == 0:
            state.timeouts += 1
            if state.timeouts > 5:
                state.current_delay = min(state.current_delay + 5.0, 60.0)

        # Detect healthy recovery -- if last 10 requests all succeeded, reduce delay
        if len(state.response_times) >= 10:
            recent = state.response_times[-10:]
            if all(t < 2.0 for t in recent) and state.current_delay > 0:
                state.current_delay = max(0, state.current_delay - 0.5)

    async def wait_before_request(self, host: str):
        """Called before every HTTP request. Applies adaptive delay."""
        state = self.host_state.get(host)
        delay = (state.current_delay if state else 0) + self.global_backoff
        if delay > 0:
            # Add jitter to avoid thundering herd
            jitter = delay * 0.2 * (hash(host) % 100 / 100)
            await asyncio.sleep(delay + jitter)

    async def _reduce_concurrency(self, category: str, factor: float):
        """Replace semaphore with lower concurrency."""
        current = self.semaphores[category]._value
        new_limit = max(1, int(current * factor))
        self.semaphores[category] = asyncio.Semaphore(new_limit)

class HostRateState(BaseModel):
    total_requests: int = 0
    rate_limit_hits: int = 0
    waf_blocks: int = 0
    timeouts: int = 0
    current_delay: float = 0.0
    concurrency_reduction: int = 0
    waf_triggered: bool = False
    response_times: list[float] = []
```

#### Behavioral Anomaly Detector

```python
class BehavioralAnalyzer:
    """
    Passive analysis of response characteristics to detect subtle misconfigurations
    and behavioral weaknesses that status-code-only checking misses.
    """

    async def analyze_host(
        self, client: httpx.AsyncClient, host: str, base_url: str
    ) -> list[BehavioralFinding]:
        findings = []

        # Test 1: X-Forwarded-For trust
        # Send request with spoofed internal IP. If response differs, proxy trusts the header.
        resp_normal = await client.get(base_url, timeout=5.0)
        resp_spoofed = await client.get(
            base_url,
            headers={"X-Forwarded-For": "127.0.0.1"},
            timeout=5.0
        )
        if resp_spoofed.status_code != resp_normal.status_code or \
           abs(len(resp_spoofed.text) - len(resp_normal.text)) > 500:
            findings.append(BehavioralFinding(
                host=host, test="xff_trust",
                evidence="Response changed when X-Forwarded-For: 127.0.0.1 was sent",
                severity="medium", confidence=0.7,
                implication="Server may trust X-Forwarded-For for access control decisions",
            ))

        # Test 2: User-Agent based content variation (cloaking)
        ua_bot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ua_normal = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        resp_bot = await client.get(base_url, headers={"User-Agent": ua_bot}, timeout=5.0)
        resp_user = await client.get(base_url, headers={"User-Agent": ua_normal}, timeout=5.0)
        if abs(len(resp_bot.text) - len(resp_user.text)) > 1000:
            findings.append(BehavioralFinding(
                host=host, test="ua_cloaking",
                evidence=f"Response size differs by {abs(len(resp_bot.text) - len(resp_user.text))} bytes between bot and browser UA",
                severity="low", confidence=0.5,
                implication="Server serves different content to crawlers vs browsers",
            ))

        # Test 3: HTTP method tampering
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
            try:
                resp = await client.request(method, base_url, timeout=3.0)
                if method == "TRACE" and resp.status_code == 200:
                    findings.append(BehavioralFinding(
                        host=host, test="trace_enabled",
                        evidence="HTTP TRACE method returns 200 OK",
                        severity="medium", confidence=0.9,
                        implication="TRACE enabled -- potential XST (Cross-Site Tracing) vector",
                    ))
                if method in ["PUT", "DELETE"] and resp.status_code in [200, 201, 204]:
                    findings.append(BehavioralFinding(
                        host=host, test=f"{method.lower()}_allowed",
                        evidence=f"HTTP {method} on / returns {resp.status_code}",
                        severity="high", confidence=0.6,
                        implication=f"Dangerous HTTP method {method} may be enabled on root",
                    ))
            except Exception:
                pass

        # Test 4: Timing analysis (response time variance)
        # Make 5 identical requests, measure timing. High variance may indicate
        # load balancer rotation, cache inconsistency, or backend instability.
        times = []
        for _ in range(5):
            t0 = asyncio.get_event_loop().time()
            try:
                await client.get(base_url, timeout=5.0)
            except Exception:
                pass
            times.append(asyncio.get_event_loop().time() - t0)
        if times:
            avg = sum(times) / len(times)
            variance = sum((t - avg) ** 2 for t in times) / len(times)
            if variance > 1.0:
                findings.append(BehavioralFinding(
                    host=host, test="response_timing_variance",
                    evidence=f"Response time variance={variance:.2f}s across 5 requests (avg={avg:.2f}s)",
                    severity="info", confidence=0.4,
                    implication="High timing variance may indicate load balancer, cache miss, or instability",
                ))

        # Test 5: Host header injection
        resp_evil = await client.get(
            base_url,
            headers={"Host": "evil.example.com"},
            timeout=5.0
        )
        if "evil.example.com" in resp_evil.text:
            findings.append(BehavioralFinding(
                host=host, test="host_header_injection",
                evidence="Injected Host header 'evil.example.com' reflected in response body",
                severity="high", confidence=0.85,
                implication="Host header injection -- potential cache poisoning or password reset hijacking",
            ))

        return findings

class BehavioralFinding(BaseModel):
    host: str
    test: str
    evidence: str
    severity: str
    confidence: float
    implication: str
```

---

## 7. Updated Architecture Summary

The complete engine now has **15 logical stages** (12 base + 3 elite):

```
STAGE  1: Surface Recon          (CT logs, DNS brute, WHOIS, reverse DNS, zone transfer)
STAGE  2: Network Scan           (TCP connect, banner grab, service fingerprint, ASN)
STAGE  3: OS Fingerprint         (banner inference, headers, TTL, container indicators)
STAGE  4: TLS / Crypto Handshake (version probe, cipher enum, cert chain, OCSP, STARTTLS)
STAGE  5: Crypto Analysis        (algorithm classification, HNDL, PQC readiness)
STAGE  6: CDN / WAF / Proxy      (CNAME CDN, header WAF, cloud ASN, proxy detection)
STAGE  7: Tech Fingerprint       (headers, HTML, scripts, cookies, favicon, error pages)
STAGE  8: Web / API Discovery    (security headers, cookies, CORS, OpenAPI, GraphQL, well-known)
STAGE  9: Hidden Discovery       (robots, sitemap, path fuzz, backups, JS route extraction)
STAGE 10: Vulnerability Engine   (rule-based, CVE correlation, behavioral probes, misconfig)
STAGE 11: Correlation + Risk     (graph build, attack paths, scoring, scan diff)
STAGE 12: CBOM + Reporting       (CERT-IN CBOM, recommendations, export bundles)
--- ELITE LAYER (depth: aggressive) ---
STAGE 13: Advanced Fingerprint   (TCP stack analysis, raw SYN probe if root, multi-probe)
STAGE 14: Attack Surface         (stateful crawl, parameter fuzz, GraphQL deep, exploit chains)
STAGE 15: Behavioral Analysis    (XFF trust, UA cloaking, method tampering, timing, host injection)
--- APEX LAYER (depth: aggressive + browser/AI enabled) ---
STAGE 16: Browser Engine         (Playwright SPA rendering, DOM crawl, XSS validation, auth flow)
STAGE 17: AI Adaptive Decisions  (LLM-driven scan intelligence via LM Studio, runs after every stage)
STAGE 18: Priority Scheduling    (host triage, early stopping, confidence filtering -- runs continuously)
```

Stage 17 (AI Adaptive) is not a sequential stage -- it runs as a **hook after every stage** when enabled. Stage 18 (Scheduler) is a **continuous governor** that wraps the entire pipeline.

Stages 13-18 run **conditionally**:

- 13-15 run when `scan_depth: "aggressive"`
- 16 runs when `scan_depth: "aggressive"` and Playwright is installed (graceful skip otherwise)
- 17 runs when LM Studio is reachable (graceful fallback to empty actions)
- 18 always runs (it governs the pipeline even in `"fast"` mode)

### Updated folder structure

```
Backend/app/scanner/
  engines/
    ...existing 12 engine files...
    advanced_fingerprint.py     # Stage 13: TCP stack + multi-probe OS fingerprint
    attack_surface.py           # Stage 14: Crawler + fuzzer + GraphQL + exploit chains
    adaptive.py                 # AdaptiveRateController + BehavioralAnalyzer (Stage 15)
    browser_engine.py           # Stage 16: Playwright SPA crawler + DOM XSS + auth flow
    ai_adaptive.py              # Stage 17: LLM-driven adaptive decisions via LM Studio
    scheduler.py                # Stage 18: SmartScheduler + ConfidenceFilter + HostPriority
  data/
    ...existing data files...
    os_fingerprint_db.json      # TCP signature database for OS matching
    exploit_chains.json         # Chain pattern definitions
    fuzz_payloads.json          # Injectable test payloads
```

---

## 8. Innovation Features (updated)

**Attack-path intelligence** -- The correlation graph enables multi-hop attack path discovery: `Internet -> exposed admin panel -> outdated CMS -> CVE -> same-IP internal API`. Top paths are priority-ranked in the executive summary.

**AI-driven adaptive scanning** -- After each stage, findings are summarized and sent to the LM Studio LLM. The LLM analyzes the data and returns structured JSON actions (escalate host, add paths, enable browser scan, etc.). Actions are validated against a whitelist before execution. If LLM is unavailable, the pipeline continues normally.

**Browser-based validation** -- Playwright headless Chromium renders SPAs, executes JavaScript, intercepts network requests, and validates XSS payloads in a real DOM context. Catches DOM-based vulnerabilities and client-side secrets that regex-on-HTML misses entirely.

**Smart priority scheduling** -- Hosts are triaged after Stage 2 (Network) into tiers: critical (exposed DBs), high (remote access), standard (web), low (minimal surface). Expensive stages (crawling, fuzzing, browser) only run on high-priority hosts. Hard budget caps (15 min, 10k requests) trigger early stopping.

**Confidence filtering** -- All findings pass through a confidence threshold filter before reporting. Thresholds adapt to scan depth: aggressive mode shows more speculative findings, fast mode suppresses anything below 70% confidence. Reduces false positives without discarding real findings.

**Evidence-backed output** -- Every score deduction links to the specific raw observation that caused it. "Score -15 because: host api.example.com accepts TLS 1.0 connections (probe at 2026-04-16T10:23:45Z)."

**Scan diff engine** -- Compare any two scans for the same domain. Output: new assets, removed assets, new findings, resolved findings, score change. Enables continuous monitoring posture.

**Self-improving heuristics** -- Store analyst feedback (false positive markings) in MongoDB. Over time, auto-downgrade confidence for patterns with high false-positive rates.

---

## 9. Implementation Roadmap (updated)

### Phase 1 -- MVP Core (Build first)

Build the minimum custom engine that replaces all external tools and produces a usable scan:

1. `app/scanner/pipeline.py` -- PipelineManager, ScanContext, ScanStage base, RetryManager
2. `app/scanner/engines/adaptive.py` -- AdaptiveRateController (replaces basic ThrottleController from day one)
3. `app/scanner/engines/recon.py` -- CT log + DNS brute + WHOIS + reverse DNS (replaces subfinder/amass/dnsx)
4. `app/scanner/engines/network.py` -- TCP connect scanner + banner grabber + service fingerprint (replaces nmap)
5. `app/scanner/engines/tls_engine.py` -- TLS version probe + cipher enum + cert extraction (replaces sslscan/testssl/zgrab2/openssl)
6. `app/scanner/engines/crypto_analysis.py` -- Algorithm classifier + HNDL assessment (extends crypto_analyzer.py)
7. `app/scanner/engines/reporting.py` -- CBOM builder + recommendations (wraps existing cbom_generator + recommendation_engine)
8. `app/scanner/models.py` -- All new Pydantic models
9. Data files: `subdomain_wordlist.txt`, `service_signatures.json`, `cipher_registry.json`
10. Wire into `routes.py` -- Replace `_run_scan_pipeline` to call PipelineManager

### Phase 2 -- Deep Intelligence (Build second)

Add the layers the current system completely lacks:

1. `app/scanner/engines/os_fingerprint.py` -- Banner + header + TTL OS detection
2. `app/scanner/engines/cdn_waf.py` -- CDN/WAF/proxy/cloud detection
3. `app/scanner/engines/tech_fingerprint.py` -- Wappalyzer-style tech stack detection
4. `app/scanner/engines/web_discovery.py` -- Full security header + cookie + CORS + API schema audit
5. `app/scanner/engines/hidden_discovery.py` -- Path fuzzing + JS extraction + backup detection
6. Data files: `tech_signatures.json`, `common_paths.txt`, `cloud_ip_ranges.json`

### Phase 3 -- Intelligence Layer (Build third)

Connect everything into a coherent intelligence system:

1. `app/scanner/engines/vuln_engine.py` -- Rule-based vuln detection + CVE matching
2. `app/scanner/engines/correlation.py` -- Asset graph + risk scoring + attack paths + scan diff
3. Data files: `vuln_rules.json`
4. Update all dashboard API endpoints to serve the richer data
5. Update frontend components to display new intelligence fields

### Phase 4 -- Elite Layer (Build fourth)

Attacker simulation, deep crawling, and behavioral intelligence:

1. `app/scanner/engines/advanced_fingerprint.py` -- TCP stack analysis (userspace tier), raw SYN probe (privileged tier, graceful skip), multi-probe OS correlation, OS fingerprint database
2. `app/scanner/engines/attack_surface.py` -- StatefulCrawler (recursive, session-aware, form+param extraction, scope-limited), ParameterFuzzer (XSS/SQLi/SSTI/redirect/command probes with baseline comparison), GraphQLTester (introspection, depth bomb, batch abuse), ExploitChainDetector (multi-step chain pattern matching)
3. `engines/adaptive.py` upgrade -- BehavioralAnalyzer (XFF trust, UA cloaking, HTTP method tampering, timing variance, host header injection)
4. Data files: `os_fingerprint_db.json`, `exploit_chains.json`, `fuzz_payloads.json`
5. Add `scan_depth` parameter to `ScanRequest` (`"fast"` | `"standard"` | `"aggressive"`) to control whether elite stages run

### Phase 5 -- Apex Layer (Build fifth)

Browser engine, AI adaptive intelligence, and smart scheduling:

1. `app/scanner/engines/browser_engine.py` -- BrowserCrawler (Playwright headless Chromium: SPA rendering, DOM-aware link extraction, JS variable/localStorage secret detection, network request interception for API call discovery), DOMXSSValidator (injects canary payloads and checks JS execution in real browser), AuthFlowAnalyzer (login form detection, CSRF check, autocomplete audit, username enumeration test, HTTP form action check)
2. `app/scanner/engines/ai_adaptive.py` -- AIAdaptiveEngine (sends stage findings to LM Studio LLM, receives structured JSON actions validated against whitelist of 10 allowed actions, stores decision log for explainability). Integrates with PipelineManager as post-stage hook.
3. `app/scanner/engines/scheduler.py` -- SmartScheduler (host priority triage after Stage 2: critical/high/standard/low tiers; early stopping on time/request budget; per-tier scan depth configuration), ConfidenceFilter (adaptive confidence thresholds per scan depth and finding type to suppress false positives)
4. Add `playwright>=1.40.0` to requirements.txt. Run `playwright install chromium` as build step.
5. Update PipelineManager: integrate AI hook after each stage, wrap pipeline in scheduler governor, add conditional stage inclusion for browser/AI based on capability detection

### What to refactor in current code

- `app/api/routes.py` -- Replace `_run_scan_pipeline` body with `PipelineManager.run()` call. Keep all GET/dashboard endpoints as-is. Add `scan_depth` field to `ScanRequest`.
- `app/db/models.py` -- Add new models (`ServiceFingerprint`, `OSFingerprint`, `TechFingerprint`, `InfrastructureIntel`, `WebAppProfile`, `HiddenFinding`, `AssetRiskScore`, `AssetIntelligence`, `FuzzFinding`, `ExploitChain`, `BehavioralFinding`, `CrawlResult`, `AdvancedOSFingerprint`, `BrowserCrawlResult`, `DOMFinding`, `ValidatedXSS`, `AuthFlowResult`, `AdaptiveAction`, `AdaptiveDecisionLog`, `HostPriority`). Extend `ScanResult` with new fields. Keep all existing models for backward compatibility.
- `app/config.py` -- Add scanner engine settings (port profiles, timeouts per stage, wordlist paths, concurrency limits, scan depth profiles, fuzz payload paths, scheduler budgets, AI adaptive toggle).
- Old `app/modules/*.py` -- **Do not delete.** Keep as fallback. New scanner package is the primary path.

### Key dependency changes to `requirements.txt`

```
dnspython>=2.4.0        # async DNS resolver (pure Python)
playwright>=1.40.0      # headless browser for SPA/DOM scanning (optional, graceful skip)
# cryptography is already present at 43.0.1
# httpx is already present at 0.27.2
# LM Studio LLM client already exists in app/modules/lm_studio_client.py
```

---

## 10. Deployment Considerations

**Current model (sufficient for hackathon and early production):**

- FastAPI `BackgroundTasks` + `asyncio` with `Semaphore(3)` for global scan concurrency. This is what exists today and works for 1-10 concurrent scans.
- MongoDB for all persistence. Motor async driver handles concurrent writes.

**Scaling model (when scan volume exceeds ~50 scans/hour):**

- Replace `BackgroundTasks` with a proper async task queue: **ARQ** (Redis-backed, async-native, lightweight) or **Celery** with Redis broker.
- Each scan becomes a queue job. Workers can be scaled horizontally (multiple processes/containers, each pulling from the queue).
- Rate limiting per user: existing `slowapi` (200/min) handles API-level. Add per-user scan quota in MongoDB (`user_quotas` collection).

**Container deployment:**

- The existing `Dockerfile` works. Add `playwright install chromium` as a build step for Stage 16.
- For horizontal scaling: run API and workers as separate containers. API enqueues jobs; workers execute them.

**Monitoring:**

- The `ScanObserver` from Section 3.5 produces structured JSON logs. Route these to any log aggregator (ELK, Loki, CloudWatch).
- Per-scan metrics are stored in the `scans` document (`stage_metrics` field) for dashboard display.

---

## 11. Final Recommendation

**Build order:** Pipeline + AdaptiveRate + Scheduler -> Recon -> Network -> TLS -> Crypto -> Reporting (Phase 1). Then OS/CDN/Tech/Web/Hidden (Phase 2). Then Vuln + Correlation (Phase 3). Then Crawl + Fuzz + Fingerprint + Chains (Phase 4). Then Browser + AI Adaptive (Phase 5).

**Architecture choice:** Keep the FastAPI monolith. The `app/scanner/` package is a clean internal boundary. No microservices, no Celery, no Redis. asyncio is sufficient. SmartScheduler governs the pipeline from day one. AI Adaptive uses the existing LM Studio client -- no new LLM infrastructure.

**Scan depth profiles:**

- `"fast"` -- Stages 1-5, 12 only. Quick crypto posture check. 30-60 seconds. Scheduler governs.
- `"standard"` -- Stages 1-12. Full intelligence scan. 2-5 minutes. AI adaptive enabled if LLM available.
- `"aggressive"` -- All 18 stages. Deep crawl, parameter fuzzing, browser DOM analysis, exploit chains, AI-driven adaptive probing. 5-15 minutes. Full scheduler budget.

**What makes this industry-tier:**

1. Zero external binary dependencies -- pure Python engine
2. Complete cipher matrix -- every accepted cipher, not just negotiated
3. Stateful recursive crawling -- finds forms, parameters, and hidden API calls
4. Parameter fuzzing with baseline comparison -- detects XSS, SQLi, SSTI, redirects
5. Browser-based XSS validation -- confirms execution in real DOM, eliminates false positives
6. Exploit chain detection -- multi-step attack path narratives, not isolated findings
7. AI-driven adaptive scanning -- LLM analyzes findings and directs deeper probing in real-time
8. Smart priority scheduling -- host triage, early stopping, confidence filtering
9. Adaptive rate control -- detects WAF/rate-limiting and auto-adjusts
10. Behavioral analysis -- XFF trust, cloaking, method tampering, host injection
11. TCP stack fingerprinting -- both userspace and privileged tiers
12. SPA/DOM crawling -- Playwright renders JS apps, intercepts API calls, finds client-side secrets
13. Auth flow analysis -- login form audit, CSRF, username enumeration, HTTP action check
14. GraphQL deep testing -- introspection, depth limits, batch abuse
15. Evidence-backed scoring -- every deduction traces to a raw observation
16. CERT-IN CBOM compliance -- Annexure-A element mapping
17. HNDL risk assessment -- quantum threat model specific to banking
18. Confidence-based filtering -- adaptive thresholds per scan depth suppress false positives

