# Web & API Endpoints Discovery Engine Audit

## 1. Executive Verdict
The Web & API Discovery Engine represents a significant intended capability upgrade over the legacy `headers_scanner.py`, introducing asynchronous probing, OpenAPI/GraphQL schema detection, CORS auditing, and hidden path fuzzing. However, it is currently **SEVERELY BROKEN** in production. A Pydantic type-validation error entirely destroys the output data, meaning the engine currently contributes **zero** web profile information to the pipeline. Furthermore, its target acquisition logic hardcodes ports (ignoring discovered service ports) and it completely lacks SSRF and redirect-scope protections.

**Verdict: BROKEN / PARTIALLY IMPLEMENTED (P0 / P1 blocking issues)**

## 2. Actual Implementation Discovered
| Component | File | Class/Function | Status | Called By | Responsibility |
| --------- | ---- | -------------- | ------ | --------- | -------------- |
| Web Engine | `app/scanner/engines/web_discovery.py` | `WebAPIDiscoveryEngine` | ACTIVE | PipelineManager | Headers, CORS, Cookies, API Schemas, Well-known |
| Hidden Engine | `app/scanner/engines/hidden_discovery.py` | `HiddenDiscoveryEngine` | ACTIVE | PipelineManager | Robots, sitemaps, JS routes, sensitive paths |
| Legacy Headers | `app/modules/headers_scanner.py` | `scan_headers` | LEGACY | Legacy Router | Sync HEAD security header checks |

## 3. Intended Responsibility Boundary
The engine intends to perform:
- HTTP/HTTPS service profiling.
- Security header, Cookie, and CORS auditing.
- Well-known resource probing.
- API Schema discovery (OpenAPI, Swagger, GraphQL).
- Path fuzzing for sensitive files (`.env`, `robots.txt`, admin paths).
- Extraction of hidden API routes from Javascript files.

## 4. Security Boundary: Discovery vs Exploitation
**OBSERVED BEHAVIOR**: The engine correctly remains within the bounds of **DISCOVERY**. It uses `GET` and `POST` (for GraphQL introspection) but does not attempt vulnerability exploitation. However, its path fuzzing (e.g., retrieving `.env` and `.git/config` files) borders on light vulnerability scanning, effectively pulling sensitive material into the scan context.

## 5. Target Acquisition
**POTENTIAL ISSUE (P1)**: The engine acquires targets from `ctx.services` or `ctx.subdomains`. However, when constructing the URL, it simply builds `https://{host}/`. It **completely ignores the `port`** field from the service discovery stage. If a web service was discovered on `8443` or `8080`, this engine will still only probe `443` and `80`.

## 6. HTTP/HTTPS Discovery
**OBSERVED BEHAVIOR**: Probes `https://`. If a connection error occurs, it falls back to `http://`. Due to the port ignorance mentioned above, it only ever probes standard ports.

## 7. Hostname/IP/SNI Handling
**POTENTIAL ISSUE**: If the `host` provided by target acquisition is an IP address, the engine will send requests to `https://<IP>/`. This means the SNI and `Host` header will be the IP address, breaking virtual-host routing. It does not preserve the original hostname mapping.

## 8. Redirect Handling
**POTENTIAL ISSUE (P1)**: `WebAPIDiscoveryEngine` uses `follow_redirects=True` for the initial root profile fetch and JS extraction. However, it implements **no scope control**. If `http://target.com/` redirects to `https://attacker.com/`, the scanner will silently follow the redirect, profiling the attacker domain, and potentially downloading and executing Regex extraction on attacker-controlled Javascript.

## 9. URL Normalization
**UNKNOWN / WEAK**: There is no sophisticated URL normalization library used. Paths are constructed via raw string concatenation (`f"https://{host}{path}"`). Path deduplication relies entirely on string dictionary keys.

## 10. Crawling and Link Discovery
**OBSERVED BEHAVIOR**: The engine does **not** crawl standard HTML links (`<a href>`). It only searches for `<script src="...">` tags to download Javascript files.

## 11. JavaScript Endpoint Discovery
**POTENTIAL ISSUE (P2)**: `HiddenDiscoveryEngine._extract_js_routes` uses string-based Regex (`r'["\`]\/(?:api|v\d+|rest|graphql)[^"\`\s?#]{2,60}["\`]'`) on downloaded Javascript to find API paths. 
**False Positive Risk**: It immediately appends these strings as `HiddenFinding` records with `finding_type="api_leak"`. It does **not** verify that these endpoints actually exist. It dangerously conflates a "Discovered String Reference" with a "Verified Live Endpoint."

## 12. API Endpoint Discovery
**OBSERVED BEHAVIOR**: It relies on a hardcoded list of `API_PROBE_PATHS` (e.g., `/openapi.json`, `/swagger.json`). If found, it parses the JSON keys under `"paths"` and stores them as `documented_endpoints`. It does not actively request the endpoints themselves.

## 13. OpenAPI / Swagger Discovery
**VERIFIED FACT**: Discovers schemas by requesting paths. If `resp.json()` parses, it successfully extracts the endpoints.

## 14. GraphQL Discovery
**VERIFIED FACT**: Sends an active introspection query (`POST /graphql` with `{ __schema { types { name } } }`). If successful, it extracts schema type names.

## 15. Well-Known Resource Discovery
**VERIFIED FACT**: Probes a hardcoded list (`/.well-known/security.txt`, etc.).
**P0 CRITICAL ISSUE**: The engine builds a dictionary of results (`dict[str, dict]`) and passes it to the `WebAppProfile` constructor as `well_known_results`. However, the Pydantic schema expects a `list[WellKnownResult]`. **Runtime validation fails, raising a `ValidationError`**, and the engine completely discards the web profile for the host. 

## 16. HTTP Header / Technology Discovery
**VERIFIED FACT**: Extracts `Server` and `X-Powered-By` headers and stores them in `info_leaks`. It does not perform deep technology fingerprinting, correctly leaving that to the TechFingerprintEngine.

## 17. Authentication Endpoint Discovery
**NOT IMPLEMENTED**: Other than general hidden-path fuzzing (e.g., `/admin`), it does not specifically map authentication or OAuth endpoints.

## 18. Parameter Discovery
**NOT IMPLEMENTED**: No query, path, or form parameter discovery is performed.

## 19. Response Classification
**VERIFIED FACT**: 
- `200, 201, 204` are treated as valid schema discoveries.
- `401, 403` are safely treated as "schema exists but protected".
- `429` correctly triggers a backoff counter in the hidden discovery engine.

## 20. Content-Type Analysis
**VERIFIED FACT**: Uses `if "json" in ct` to determine if it should attempt to parse an OpenAPI schema response. 

## 21. API Version Detection
**NOT IMPLEMENTED**: Version detection only happens implicitly via Regex matches on JavaScript strings (e.g., `/v1/`).

## 22. Confidence / Evidence Model
**VERIFIED FACT**: `HiddenFinding` uses a rudimentary confidence model (`200` = 0.7, `.env` leak = 1.0). Evidence is simply recorded as the HTTP status code mapped to the path.

## 23. Deduplication
**PARTIAL**: Deduplicates fuzzed paths using `list(dict.fromkeys(...))` before requesting them, preventing duplicate outbound requests.

## 24. Scope Control
**BROKEN (P1)**: The engine does not verify that redirects or JS extraction URLs remain within the authorized domain scope.

## 25. Rate Limiting / Concurrency
**VERIFIED FACT**: Safely utilizes the Pipeline Manager's global `ctx.throttle.acquire("http_probe")` semaphore, ensuring it respects global concurrent connection limits.

## 26. Timeout / Retry Handling
**VERIFIED FACT**: Implements strict 5-10 second timeouts. No retries are attempted (`max_retries=0`). 

## 27. TLS Handling
**OBSERVED BEHAVIOR**: Creates its own `httpx.AsyncClient(verify=False)`. It duplicates the TLS handshake cost rather than reusing data from the `TLSCryptoEngine`.

## 28. CDN/WAF Interaction
**VERIFIED FACT**: Excellent integration. The `HiddenDiscoveryEngine` checks `ctx.cdn_waf_intel`. If a WAF is detected, it severely truncates the fuzzing wordlist to avoid triggering IP bans or polluting results with WAF challenge pages.

## 29. Error Handling
**OBSERVED BEHAVIOR**: Highly permissive. Swallows almost all `httpx` exceptions and parsing errors using `except Exception: pass`, which hides underlying implementation bugs.

## 30. Parser / Response Safety
**POTENTIAL ISSUE (P2)**: When reading responses (e.g., for JS extraction or confidence checking), it evaluates `resp.text[:2000]`. In `httpx`, `resp.text` reads and decodes the **entire response body into memory** before slicing it. If the server returns a 10GB file on `/`, this will cause a catastrophic Out-Of-Memory (OOM) crash.

## 31. SSRF / Scanner Abuse Analysis
**POTENTIAL ISSUE (P1)**: The engine does not filter out `localhost`, `127.0.0.1`, or RFC1918 internal addresses. If a redirect points to `http://169.254.169.254/` (AWS Metadata), the scanner will happily fetch it and parse it for APIs.

## 32. Sensitive Data Handling
**OBSERVED BEHAVIOR**: `well_known_results` stores up to 500 characters of `content_preview`. If `.env` files are found, their contents are evaluated for risk but not stored in full.

## 33. Data Models
**BROKEN**: `WebAppProfile` and `HiddenFinding`. As established in section 15, `well_known_results` type mismatch destroys the output.

## 34. ScanContext Integration
**VERIFIED FACT**: Uses `MergeStrategy.OVERWRITE`. It writes to `ctx.web_profiles` and `ctx.hidden_findings`.

## 35. Pipeline Integration
**OBSERVED BEHAVIOR**: Serves as Stage 8 & 9. Downstream vulnerability engines loop over `ctx.web_profiles`. Because of the schema crash, downstream engines effectively receive zero web targets.

## 36. Persistence
**VERIFIED FACT**: Data is dumped to MongoDB via `routers/common.py`. 

## 37. API Exposure
**UNKNOWN**: API exposure depends on the previously identified systemic missing router-decorator issues.

## 38. Frontend Consumption
**UNKNOWN**: Frontend tables will likely render empty for "Web Profiles" due to the backend Pydantic crash.

## 39. Legacy Implementation Comparison
The legacy `headers_scanner.py` only issued a synchronous `HEAD` request to check for security headers. The new engine is vastly superior in intended capabilities (async, API discovery, CORS, Cookies, fuzzing), but inferior in reliability (currently crashing on every run).

## 40. Runtime Verification
**VERIFIED FACT**: A local `scratch/test_web.py` harness was executed. The runtime verification **proved** that `pydantic_core._pydantic_core.ValidationError: 1 validation error for WebAppProfile well_known_results Input should be a valid list` is actively crashing the engine for any host it profiles.

## 41. Performance Audit
**PARTIAL**: O(N) where N is the number of services. Bounded by strict timeouts and concurrency limits. Memory usage is unbounded due to unsafe `resp.text` evaluation on large files.

## 42. Security Audit
**BROKEN**: Unrestricted redirects and lack of SSRF protection means the scanner can be weaponized to probe internal infrastructure.

## 43. Evidence Quality
**PARTIAL**: Evidence is mostly rudimentary (`HTTP 200 on /path`).

## 44. False Positive / False Negative Analysis
- **False Positive**: JavaScript Regex extraction creates findings with `finding_type="api_leak"` without verifying the endpoint is live.
- **False Negative**: Ignores actual discovered ports, resulting in zero discovery for services hosted on non-standard ports (e.g., `8443`).

## 45. Regression Analysis
- **NEW CAPABILITY**: Async probing, GraphQL/OpenAPI schema discovery, JS extraction, WAF-aware fuzz throttling.
- **LOST CAPABILITY**: Currently lost all basic header scanning functionality due to the Pydantic crash regression.

## 46. Capability Matrix
| Capability                        | Status | Evidence |
| --------------------------------- | ------ | -------- |
| HTTP/HTTPS discovery              | PARTIAL | Hardcodes 443/80, ignores discovered ports. |
| Non-standard port discovery       | BROKEN  | Hardcodes URL to `https://{host}/` |
| Redirect handling                 | PARTIAL | Follows redirects, but no scope control. |
| URL normalization                 | NOT IMPLEMENTED | Simple string concatenation. |
| HTML crawling                     | NOT IMPLEMENTED | Only extracts `<script src>`. |
| JavaScript endpoint discovery     | VERIFIED | Uses Regex. Generates False Positives. |
| API endpoint discovery            | VERIFIED | Probes hardcoded OpenAPI/Swagger dictionary. |
| OpenAPI/Swagger discovery         | VERIFIED | Parses JSON paths. |
| GraphQL discovery                 | VERIFIED | Performs active schema introspection. |
| Well-known discovery              | BROKEN | Causes Pydantic ValidationError crash. |
| HTTP method discovery             | NOT IMPLEMENTED | |
| Parameter discovery               | NOT IMPLEMENTED | |
| Authentication endpoint discovery | NOT IMPLEMENTED | |
| Response classification           | VERIFIED | Maps 200, 401, 403, 404 appropriately. |
| Technology/header discovery       | VERIFIED | Minimal Server/X-Powered-By leaks. |
| Endpoint confidence               | VERIFIED | Hardcoded heuristic scoring. |
| Deduplication                     | PARTIAL | Dict key deduping. |
| Scope control                     | BROKEN | Open to SSRF and external redirect abuse. |
| Rate limiting                     | VERIFIED | Uses `ctx.throttle`. |
| Timeout handling                  | VERIFIED | Strict httpx timeouts. |
| Error isolation                   | BROKEN | Schema validation error crashes the entire host loop. |
| SSRF protection                   | BROKEN | Follows redirects to any IP/Host. |
| Sensitive-data handling           | VERIFIED | `content_preview` limited to 500 chars. |

## 47. P0/P1/P2/P3 Findings

**ID: WEB-01 (P0) - Pydantic Schema Crash on Well-Known Results**
- **File**: `app/scanner/engines/web_discovery.py`
- **Observed**: `well_known_results` is constructed as a `dict` but `WebAppProfile` expects a `list`. 
- **Impact**: Throws a `ValidationError`, completely discarding the entire web profile for the host. 

**ID: WEB-02 (P1) - Discovered Ports Ignored**
- **File**: `app/scanner/engines/web_discovery.py` (`_profile_host`)
- **Observed**: Constructs URLs using `https://{host}/`, completely ignoring the `port` field from target acquisition.
- **Impact**: Fails to scan any web applications hosted on non-standard ports.

**ID: WEB-03 (P1) - Missing Scope Control & SSRF Vulnerability**
- **File**: `app/scanner/engines/web_discovery.py` & `hidden_discovery.py`
- **Observed**: `follow_redirects=True` allows the scanner to be redirected to arbitrary third-party domains or internal RFC1918 addresses.
- **Impact**: The scanner can be weaponized to attack internal infrastructure or pollute the scan context with third-party domain data.

**ID: WEB-04 (P2) - Unbounded Response Memory Consumption**
- **File**: `app/scanner/engines/hidden_discovery.py`
- **Observed**: Accesses `resp.text[:2000]` which forces `httpx` to download and buffer the entire response body in memory.
- **Impact**: High risk of Out-Of-Memory (OOM) crashes if a server returns a massive file.

**ID: WEB-05 (P2) - Javascript Reference False Positives**
- **File**: `app/scanner/engines/hidden_discovery.py`
- **Observed**: Regex extraction from JS files immediately logs findings as live "api_leaks" without sending a verification request.
- **Impact**: Pollutes the dashboard with non-existent or parameterized paths that are not active.

## 48. KEEP UNTOUCHED
- WAF-aware wordlist truncation logic (`ctx.cdn_waf_intel` check).
- GraphQL Introspection implementation.
- `ScanContext.throttle` semaphore concurrency integration.
- CORS Permissive Origin verification logic.

## 49. Required Fix Order
1. Fix the P0 Pydantic `dict` to `list` mapping crash in `web_discovery.py`.
2. Fix the URL construction to respect the `port` from `ctx.services`.
3. Implement scope control to abort if a redirect resolves to an external domain or internal IP.
4. Convert `resp.text` reads to size-limited asynchronous streaming reads.
5. Move Javascript extracted routes to a "discovered_references" array rather than logging them directly as live findings.

## 50. Final Verdict
The Web & API Discovery Engine is an ambitious and capable module that is currently **failing entirely in production** due to a fundamental data-type mismatch. Even if the crash is resolved, it requires critical architectural fixes to prevent scope expansion (SSRF) and to properly honor the ports discovered during the network scanning phase. It cannot be trusted as an authoritative web discovery engine until WEB-01 and WEB-02 are resolved.
