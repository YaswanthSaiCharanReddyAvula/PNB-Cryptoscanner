# ECDAT NETWORK SCAN ENGINE — AUDIT REPORT

## 1. Executive Summary
The ECDAT Network Scan Engine actually consists of two parallel implementations: a legacy `asset_discovery.py` relying on `nmap` subprocesses, and a newer `network.py` (`NetworkScanEngine`) utilizing pure-Python `asyncio.open_connection` TCP socket scanning and regex-based banner grabbing. 
The newer engine provides a unified ASPM pipeline approach that is decoupled from external binaries. However, it currently lacks UDP scanning, granular target normalization, and strict target scope authorization (e.g. CIDR filtering for internal IPs).

## 2. Current Implementation
* **`network.py`**: Modern `asyncio` TCP connect scanner, banner grabber, and regex-based service fingerprinting.
* **`asset_discovery.py`**: Legacy pipeline that shells out to `nmap -sT -p <ports> --open -oG - <target>`.

## 3. Actual Execution Path
* **Path A (Adaptive ASPM)**: `API /scan` → `scan.py start_scan()` → `common.py _run_scan_pipeline_gated()` → `common.py _run_custom_scan_pipeline()` → `DualTrackPipelineManager` → `NetworkScanEngine.execute()`.
* **Path B (Legacy 8-Stage)**: `API /scan` → `scan.py start_scan()` → `common.py _run_scan_pipeline_gated()` → `common.py _run_scan_pipeline()` → `asset_discovery.discover_assets()` → `nmap` subprocess.

## 4. File/Module Inventory
* `Backend/app/scanner/engines/network.py`: Modern TCP engine + banner grabber.
* `Backend/app/modules/asset_discovery.py`: Legacy shell-out pipeline (Subfinder, Amass, DNSX, HTTPX, Nmap).
* `Backend/app/api/routers/scan.py`: Route definitions and background task dispatch.
* `Backend/app/api/routers/common.py`: Pipeline multiplexer (`_run_scan_pipeline_gated`).

## 5. Duplicate Implementations
Network scanning is duplicated across `network.py` (new) and `asset_discovery.py` (old).

| File | Responsibility | Used? | Status | Decision | Reason |
| --- | --- | --- | --- | --- | --- |
| `network.py` | TCP scanning | Yes | Working | KEEP | Canonical modern implementation |
| `asset_discovery.py` | Legacy scanning | Yes | Legacy | DEPRECATE | Duplicate; dangerous external binary reliance |

## 6. Dependency Inventory
* **nmap**: Used in `asset_discovery.py` via `asyncio.create_subprocess_exec`. Called as `nmap -Pn -sT -p <ports> --open -oG - <target>`. Requires `nmap` installed on Kali VM.
* **dns.asyncresolver**: Used in `network.py` for Cymru ASN lookups.

## 7. Target Handling
* `network.py`: Derives targets from `ctx.ip_map` (from Recon stage) or `ctx.subdomains`. Does not perform ownership validation, CIDR restrictions, or private IP filtering. This introduces potential SSRF/internal network scanning risks if a user can supply `localhost` or `10.0.0.1` as a subdomain via DNS rebinding.
* `asset_discovery.py`: Uses `domain_regex` but also lacks strict IP range checks.

## 8. Port Scanning
* `network.py`: Port selection is based on `PORT_PROFILES` ("web", "banking", "standard"). It adaptively reduces to `CRITICAL_PORTS` if a threshold of closed ports is met.
* `asset_discovery.py`: Uses `ports` argument or `settings.DEFAULT_PORTS`. Passed directly to nmap.

## 9. TCP Implementation
* `network.py`: Uses `asyncio.open_connection(ip, port)`. Distinguishes `open` (success), `closed` (ConnectionRefused/ConnectionReset), `filtered` (Timeout), and `error` (OSError).
* `asset_discovery.py`: Nmap uses `-sT` (TCP connect scan). Only extracts `/open` matches via regex.

## 10. UDP Implementation
STATUS = NOT IMPLEMENTED. Neither implementation supports UDP scanning natively (no `asyncio.create_datagram_endpoint` or `nmap -sU`).

## 11. Concurrency
* `network.py`: Batches of 50 (`_BATCH_SIZE`) using `asyncio.gather`. Regulated globally per-scan by `ctx.throttle.acquire("tcp_scan")` (AdaptiveRateController).
* `asset_discovery.py`: Loops over targets sequentially. Inside `scan_ports`, nmap handles concurrency per target, but targets are processed one by one.

## 12. Timeouts
* `network.py`: TCP connect timeout is hardcoded to 2.0s. Banner grab TCP connect is 3.0s, read timeout is 2.0s.
* `asset_discovery.py`: Uses `TOOL_TIMEOUT` (configurable, max 900s) for the entire nmap process.

## 13. Retries
Neither implementation appears to have explicit TCP connection retries with backoff. Network scanning is one-shot per port.

## 14. Rate Limiting
* `network.py`: Handled via `ctx.throttle` (AdaptiveRateController), which limits global concurrent tasks dynamically.
* `asset_discovery.py`: Unregulated externally; nmap uses its own internal rate limiting.

## 15. Service Detection
* `network.py`: Yes. Sends port-specific protocol probes (`BANNER_PROBES`). Matches banners against regex definitions in `data/service_signatures.json`.
* `asset_discovery.py`: No. It relies purely on the nmap open port list and does not execute `-sV` for service detection.

## 16. Banner Handling
* `network.py`: Banners are fetched via stream readers, truncated to 512 bytes (`raw_banner=banner[:512]`), and stored in the `ServiceFingerprint` model. There is no active sanitization of sensitive tokens or credentials that might bleed into the banner.

## 17. TLS Integration
* `network.py`: Outputs `ServiceFingerprint` objects. The `DualTrackPipelineManager` later feeds these open ports into `TLSCryptoEngine`. It correctly defers full TLS analysis.
* `asset_discovery.py`: Returns a basic port list which the legacy pipeline feeds into `tls_scanner.py`.

## 18. Evidence Handling
* `network.py`: Evidence is captured as `raw_banner` within the `ServiceFingerprint`. However, a strict graph-based `Evidence` model that separates the observation from the service is missing.

## 19. Asset Correlation
* `network.py`: Iterates over `ctx.ip_map` (which maps IPs to subdomains) and produces an `assets` payload that correlates the discovered open ports back to the originating hostnames.

## 20. Database/Persistence
Neither engine persists to the DB directly. They return data objects to `common.py`, which aggregates output across all stages and executes a single `$set` update on the `SCANS_COLLECTION`. This fully overwrites the prior state of the `scan_id`.

## 21. Scan History
Handled at the router level by maintaining discrete scan documents (`/scans/history`). The `/scans/diff` endpoint provides manual state transition comparison (e.g., closed vs open), but the network engine itself has no stateful historical awareness.

## 22. Error Handling
* `network.py`: Suppresses network errors (timeouts, resets, OS errors) and maps them cleanly into state fields (`closed`, `filtered`, `error`). Does not crash the pipeline.
* `asset_discovery.py`: Suppresses subprocess exceptions. If nmap fails or times out, it falls back to a hardcoded `[443]`. This is extremely dangerous as it hallucinates an open port regardless of reality.

## 23. Logging
Logs start, progress, and completion metrics. Banners are not logged explicitly, reducing PII/credential leakage risks in operational log files.

## 24. Security Assessment
* **Command Injection**: `asset_discovery.py` passes `ports` directly to `nmap` without sanitization. If a user controls the `ports` string, command injection is highly likely.
* **SSRF / Internal Scanning**: Target hostnames are DNS-resolved locally. If a user provides a public domain whose DNS resolves to an internal cloud metadata IP (`169.254.169.254`) or loopback, the engine will probe it.
* **Resource Exhaustion**: `network.py` uses fixed batch sizes (50) and throttle limits, which successfully mitigate rapid socket exhaustion.

## 25. Performance Assessment
`network.py` uses lightweight `asyncio` sockets, bypassing subprocess execution overhead. By managing max concurrency via `_BATCH_SIZE=50`, it avoids hitting `ulimit` (file-descriptor) maximums common on Linux when opening thousands of simultaneous TCP connections.

## 26. Platform Compatibility
Kali Linux VM. `network.py` uses pure Python `asyncio`, making it highly portable. `asset_discovery.py` strictly requires `nmap` in the `$PATH` of the host system.

## 27. API Integration
The `/scan` POST request triggers the backend pipeline. Output is JSON serialized and stored into MongoDB, subsequently fetched via `GET /results/{domain}` by the Frontend.

## 28. WebSocket Integration
The `DualTrackPipelineManager` broadcasts intermediate `track_b_summary`, `tls_finding`, and `cbom_summary` events. The Network Engine does not emit real-time "port discovered" events explicitly inside `network.py`.

## 29. Test Coverage
UNKNOWN — Requires runtime verification, but no explicit `tests/` directory was reviewed. Must assume test coverage is minimal or missing.

## 30. Mock/Test Data
`asset_discovery.py` hallucinates `[443]` on an nmap failure. This acts as a dangerous pseudo-mock fallback in production.

## 31. Configuration
* `network.py`: Uses `PORT_PROFILES`, `BANNER_PROBES`, `_BATCH_SIZE=50`, and `_ADAPTIVE_CLOSED_THRESHOLD=40`.
* `asset_discovery.py`: Uses `settings.DEFAULT_PORTS`.

## 32. Architecture Assessment
The current architecture of `network.py` (`NetworkScanEngine`) is reasonably well-aligned with the target ECDAT architecture. It correctly isolates TCP Probing from TLS analysis and Risk classification. However, the data model coupling to `ctx` and raw dictionaries could be formalized.

## 33. KEEP/MODIFY/REFACTOR/DEPRECATE/DELETE Matrix

| File | Responsibility | Used? | Status | Decision | Reason |
| --- | --- | --- | --- | --- | --- |
| `network.py` | TCP scanning & Banner grabbing | Yes | Working | KEEP | Native, non-blocking, modern implementation. |
| `asset_discovery.py` | Subprocess Nmap execution | Yes | Legacy | DEPRECATE | Duplicated effort; susceptible to injection; hallucinates port 443. |

## 34. Critical Issues
* **SSRF/Internal Probing Risk**: The `NetworkScanEngine` does not validate if the resolved IP addresses belong to internal CIDRs.
* **Command Injection**: `asset_discovery.py` blindly passes unsanitized port arguments to `nmap`.
* **Hallucinated Mock Data**: `asset_discovery.py` forces `[443]` as an open port if `nmap` execution fails.

## 35. Medium Issues
* **Lack of Formal Evidence Model**: Port state and banners are merged straight into the service model without an independent Evidence traceability layer.
* **WebSocket Visibility**: No granular real-time progress events are emitted during the actual TCP connection loop.

## 36. Low Issues
* **Hardcoded Timeouts**: `network.py` utilizes hardcoded `2.0s` and `3.0s` socket timeouts instead of lifting them into configuration.
* **Missing UDP Support**: UDP scanning is not implemented.

## 37. Recommended Target Architecture
The current repository already strongly mirrors the desired state through the `DualTrackPipelineManager` and `NetworkScanEngine`.

```text
                    Network Scan Engine
                            │
                     Port Scheduler
                            ↓
                    Concurrency Control (AdaptiveRateController)
                            ↓
                     TCP Probe Layer (asyncio)
                            ↓
                  Open Port Classification
                            ↓
                    Service Detection (Banner Regex)
                            ↓
                    Asset Correlation (ip_map)
                            ↓
                       Persistence (common.py)
                            ↓
                TLS / Other Engine Handoff (Pipeline)
```

## 38. Recommended Implementation Plan
* **STEP 1 — Critical fixes**: Add internal IP CIDR checks to `network.py` to prevent SSRF-like behavior.
* **STEP 2 — Canonical architecture**: Fully deprecate `scan_ports` in `asset_discovery.py` and enforce the new 15-stage ASPM pipeline exclusively.
* **STEP 3 — Data/evidence model**: Introduce a formal `Evidence` layer that captures raw observation metadata for audits.
* **STEP 4 — Configuration**: Extract all hardcoded `2.0s` timeouts and batch sizes into `settings.py`.
* **STEP 5 — Tests**: Implement unit tests for `NetworkScanEngine._scan_port` mapping exceptions to standard statuses.

## 39. Known Limitations
* UDP Scanning is not currently supported natively by the pure-Python async engine.
* Heavy reliance on generic timeouts means slow-responding services might be erroneously marked as `filtered`.

## 40. Definition of Done
The audit is complete. All findings, security gaps, duplicate functionality, and required architectural convergence strategies have been documented above. No production code was modified during this phase.
