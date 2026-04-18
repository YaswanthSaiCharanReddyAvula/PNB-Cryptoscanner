# Phase 0 — Backend baseline (inventory)

**Status:** Complete as of repo snapshot.  
**Purpose:** Single source of truth for routes, Mongo collections, scan pipeline order, config/env, and PRD traceability before Phase 1+ changes.

---

## 1. API prefix and realtime

| Surface | Base path | Notes |
|--------|-----------|--------|
| REST (scanner + dashboard) | `/api/v1` | `app.include_router(scanner_router, prefix="/api/v1")` |
| WebSocket | `/ws/scan/{scan_id}` | **No** `/api/v1` prefix — `ws_router` mounted at app root |
| Health | `/health` | Root |
| OpenAPI | `/docs`, `/openapi.json` | FastAPI default |

---

## 2. MongoDB collections (from `routes.py`)

| Constant | Collection name | Primary use |
|----------|-----------------|-------------|
| `SCANS_COLLECTION` | `scans` | Scan documents, pipeline outputs |
| `ASSET_METADATA_COLLECTION` | `asset_metadata` | Host metadata overlay (owner, env, criticality) |
| `ORG_POLICY_COLLECTION` | `org_policy` | Org crypto policy |
| `INTEGRATION_SETTINGS_COLLECTION` | `integration_settings` | Webhooks / outbound URLs |
| `EXPORT_AUDIT_COLLECTION` | `export_audit` | Export audit log |
| `MIGRATION_TASKS_COLLECTION` | `migration_tasks` | Migration tasks |
| `WAIVERS_COLLECTION` | `waivers` | Waiver workflow |
| `REGISTERED_ASSETS_COLLECTION` | `registered_assets` | External inventory import (CMDB/cloud/K8s-style) |
| `SBOM_ARTIFACTS_COLLECTION` | `sbom_artifacts` | SBOM JSON attachments per host |

See `ARCHITECTURE_DISCOVERY_INVENTORY.md` for how these feed Stage 1 discovery.

---

## 3. Route inventory → PRD mapping

All REST paths below are relative to **`/api/v1`** unless noted.

### 3.1 Scanner & results (FR-SCAN-*)

| Method | Path | Summary tag / note | PRD |
|--------|------|-------------------|-----|
| POST | `/scan` | Trigger full scan | FR-SCAN-1, FR-SCAN-4 |
| POST | `/scan/batch` | Portfolio batch | FR-SCAN-1, FR-SCAN-2 |
| GET | `/results/{domain}` | Latest scan by domain (`started_at` desc) | FR-SCAN-3 |

### 3.2 Portfolio & inventory (FR-INV-*)

| Method | Path | PRD |
|--------|------|-----|
| GET | `/scans/history` | FR-INV-1 |
| GET | `/scans/recent` | FR-INV-1 (portfolio feed, Phase 2) |
| GET | `/scans/diff` | FR-INV-1 |
| GET | `/inventory/summary` | FR-INV-2 |
| POST | `/inventory/sources/import` | Org inventory registration (extends FR-INV-2) |
| GET | `/inventory/registered` | List registered external assets |
| POST | `/inventory/sbom` | SBOM ingest (supply-chain stub) |
| PUT | `/assets/metadata` | FR-SCAN-4, FR-INV-2 |
| POST | `/assets/metadata/bulk` | FR-SCAN-4, FR-INV-2 |

### 3.3 Assets & dashboard (supporting FR-SCAN / dashboard)

| Method | Path | Tags |
|--------|------|------|
| GET | `/dashboard/summary` | Dashboard |
| GET | `/dashboard/executive-brief` | Dashboard (Phase 6, auth) |
| GET | `/dashboard/ops-snapshot` | Dashboard (Phase 7, **admin**) |
| GET | `/assets` | Assets |
| GET | `/assets/distribution` | Assets |
| GET | `/dns/nameserver-records` | DNS |
| GET | `/crypto/security` | Crypto |

### 3.4 CBOM (FR-CBOM-*)

| Method | Path | PRD |
|--------|------|-----|
| GET | `/cbom/summary` | FR-CBOM-1, FR-CBOM-2 |
| GET | `/cbom/per-app` | FR-CBOM-1, FR-CBOM-2 |
| GET | `/cbom/charts` | FR-CBOM-1 |
| GET | `/cbom/{domain}` | FR-CBOM-1 |

### 3.5 PQC (FR-PQC-*)

| Method | Path | PRD |
|--------|------|-----|
| GET | `/pqc/posture` | FR-PQC-2 |
| GET | `/pqc/vulnerable-algorithms` | FR-PQC-2 |
| GET | `/pqc/risk-categories` | FR-PQC-2 |
| GET | `/pqc/compliance` | FR-PQC-2 |

### 3.6 Cyber rating & simulation (FR-CR-*, FR-PQC-3)

| Method | Path | PRD |
|--------|------|-----|
| GET | `/cyber-rating` | FR-CR-1 |
| GET | `/cyber-rating/risk-factors` | FR-CR-1 |
| POST | `/quantum-score/simulate` | FR-PQC-3 |

### 3.7 Reporting & threat model (FR-TM-*, exports)

| Method | Path | PRD |
|--------|------|-----|
| GET | `/reporting/domains` | §5.1 Reporting |
| POST | `/reporting/generate` | §5.1 |
| GET | `/reports/export-bundle` | FR-ADM-4 adjacent / §5.1 |
| GET | `/migration/roadmap` | FR-MIG-1 |
| GET | `/threat-model/summary` | FR-TM-1 |
| GET | `/threat-model/nist-catalog` | FR-TM-1 |

### 3.8 Admin (FR-ADM-*)

| Method | Path | Auth | PRD |
|--------|------|------|-----|
| GET | `/admin/policy` | `get_current_user` | FR-ADM-1 |
| PUT | `/admin/policy` | **`require_admin`** | FR-ADM-1 |
| GET | `/admin/integrations` | `get_current_user` | FR-ADM-2 |
| PUT | `/admin/integrations` | **`require_admin`** | FR-ADM-2 |
| GET | `/admin/exports/history` | `get_current_user` | FR-ADM-4 |

### 3.9 Migration tasks & waivers (FR-MIG-*)

| Method | Path | Auth | PRD |
|--------|------|------|-----|
| GET | `/migration/tasks` | `get_current_user` | FR-MIG-2 |
| POST | `/migration/tasks` | `get_current_user` | FR-MIG-2 |
| PATCH | `/migration/tasks/{task_id}` | `get_current_user` | FR-MIG-2 |
| DELETE | `/migration/tasks/{task_id}` | `get_current_user` | FR-MIG-2 |
| POST | `/migration/tasks/seed-from-backlog` | mixed — see code | FR-MIG-2 |
| GET | `/migration/waivers` | `get_current_user` | FR-MIG-2 |
| POST | `/migration/waivers` | `get_current_user` | FR-MIG-2 |
| PATCH | `/migration/waivers/{waiver_id}` | `get_current_user` | FR-MIG-2 |
| DELETE | `/migration/waivers/{waiver_id}` | **`require_admin`** | FR-MIG-2 |

### 3.10 Discovery graph

| Method | Path | Tags |
|--------|------|------|
| GET | `/discovery/assets` | Discovery |
| GET | `/discovery/network-graph` | Discovery |

### 3.11 Auth (FR-AUTH-*)

| Method | Path | PRD |
|--------|------|-----|
| POST | `/auth/login` | FR-AUTH-1 |

### 3.11a Notifications (employee → admin)

| Method | Path | Auth |
|--------|------|------|
| POST | `/notifications` | `require_employee_only` |
| GET | `/notifications/me` | `get_current_user` |
| GET | `/admin/notifications` | `require_admin` |
| PATCH | `/admin/notifications/{notification_id}` | `require_admin` |

### 3.12 Dangerous / dev (not PRD “product” surface)

| Method | Path | Notes |
|--------|------|--------|
| DELETE | `/reset-db` | Dev — drop DB |
| POST | `/system/wipe` | Dev — wipe Mongo |

**Authoritative contract:** run the app and use **`/docs`**; this table can drift if routes are added without updating this file.

---

## 4. Scan pipeline — implemented truth vs docstring

**Source:** `_run_scan_pipeline` in `app/api/routes.py`.

### 4.1 Docstring and logs (Phase 1 aligned)

`_run_scan_pipeline` docstring and log lines now describe **8** stages; **PostgreSQL sync** is not part of the pipeline (ticket separately if needed).

- **8** logged “Stage N/8” blocks ending in **CVE / Known-Attack Mapping**.
- **DNS NS collection** runs inside discovery (after `discover_assets`, before metrics), not a separate numbered stage.

**Implemented order (Mongo `current_stage` values where set):**

| Order | Log label | `current_stage` (representative) | `progress` (approx.) |
|-------|-----------|----------------------------------|----------------------|
| 0 | Run started | `Asset Discovery` | 5 |
| 1 | Asset discovery + NS records + metrics | `Asset Discovery` | 15 |
| 2 | TLS scan | `TLS Scanning` | 20 → 35 |
| 3 | Crypto analysis | `Crypto Analysis` | 40 → 55 |
| 4 | Quantum score | `Quantum Risk` | 60 → 70 |
| 5 | CBOM report | `CBOM Generation` | 75 → 85 |
| 6 | Recommendations | `Recommendations` | 90 |
| 7 | HTTP headers | `HTTP Headers` | 95 |
| 8 | CVE mapping + complete | `CVE Mapping` → `status: completed` | 100 |

**WebSocket contract (Phase 1):** Every dict sent via `ws_manager.broadcast` is enriched with **`scan_id`** and **`ts`** (UTC `YYYY-MM-DDTHH:MM:SSZ`) in `app/core/ws_manager.py` (`enrich_ws_payload`). Payloads keep **`type`**: `status` | `log` | `metrics` | `data`.  
**DB poll path:** `app/api/v1/ws.py` uses the same enrichment and **`type`: `"status"`** on running / completed / failed frames.

### 4.2 Scan status state machine

```
pending → running → completed | failed
```

Failures: exception handler sets `status=failed`, `error`, `completed_at`, and broadcasts **`type: "status"`, `status: "failed"`** (with enriched `scan_id` / `ts`).

---

## 5. Configuration surface (`app/config.py`)

Loaded via **Pydantic Settings** from environment and optional **`.env`** (`env_file=".env"`).

| Variable | Default | Role |
|----------|---------|------|
| `APP_NAME` | `QuantumShield` | Product name |
| `APP_VERSION` | `1.0.0` | Version string |
| `DEBUG` | `False` | Debug flag |
| `LOG_LEVEL` | `INFO` | Logging |
| `MONGO_URI` | `mongodb://localhost:27017` | Mongo connection |
| `MONGO_DB_NAME` | `quantumshield` | Database name |
| `SECRET_KEY` | dev placeholder | JWT signing — **must override in prod** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` (8h) | JWT TTL |
| `CORS_ORIGINS` | `*` | CORS; `*` disables credentialed CORS per Starlette rules |
| `SCAN_TIMEOUT` | `120` | Documented “full scan” timeout (verify use vs `TOOL_TIMEOUT`) |
| `TOOL_TIMEOUT` | `30` | Per external tool subprocess cap in `asset_discovery._run_command` |
| `DEFAULT_PORTS` | long comma list | Nmap default port string |
| `MAX_SUBDOMAINS` | `50` | Cap passive enumeration before further processing |
| `MAX_BATCH_DOMAINS` | `25` | `POST /scan/batch` list cap |
| `MAX_CONCURRENT_SCANS` | `3` | Global semaphore for pipeline concurrency |

**Not in `config.py` but relevant:** SlowAPI rate limits in `main.py` (`200/min` default). JWT / OAuth2 scheme in `app/core/deps.py`.

### 5.1 Product-facing vs operational

| Tier | Settings |
|------|----------|
| **Product / demo tuning** | `MAX_SUBDOMAINS`, `MAX_BATCH_DOMAINS`, `MAX_CONCURRENT_SCANS`, `DEFAULT_PORTS`, `TOOL_TIMEOUT` |
| **Security / deploy** | `SECRET_KEY`, `CORS_ORIGINS`, `MONGO_URI`, `DEBUG` |
| **Observability** | `LOG_LEVEL` |

---

## 6. Phase 0 exit criteria (checklist)

- [x] Route list captured with method + path + primary collection impact.
- [x] PRD FR IDs mapped at category level (full line-by-line trace optional later).
- [x] Pipeline order documented; docstring / stage-9 drift **corrected in Phase 1** (see §4.1).
- [x] Mongo collection names listed.
- [x] Config/env inventory from `Settings` class.
- [x] WebSocket URL documented (`/ws/scan/{scan_id}` without `/api/v1`).

---

## 7. Phase 1 (completed from this baseline)

1. [x] `_run_scan_pipeline` **docstring** matches **8** stages; PostgreSQL sync documented as out of scope.
2. [x] **WebSocket** dict payloads get **`scan_id`** + **`ts`** via `enrich_ws_payload`; **`ws.py`** poll frames use **`type: "status"`** and the same enrichment.
3. [x] Pipeline **failure** path broadcasts **`status: failed`** after Mongo update.

---

*Maintainer: update this file when adding routes, collections, or scan stages.*
# Phase 2 — Portfolio (batch, concurrency, inventory)

**Status:** Implemented in this branch.  
**Theme (PRD §11):** Batch scans, global concurrency gate, deduplicated inventory, org metadata overlay.

---

## 1. Backend

| Mechanism | Location | Behavior |
|-----------|----------|----------|
| Global concurrency | `asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)` in `routes.py` | `_run_scan_pipeline_gated` wraps `_run_scan_pipeline`; single and batch jobs share the cap. |
| Batch queue | `POST /api/v1/scan/batch` | Dedupes domains, cap `MAX_BATCH_DOMAINS`, one `scan_id` per domain, shared `batch_id` on documents. |
| Portfolio feed | `GET /api/v1/scans/recent` | Recent scan jobs across **all** domains (sort: `started_at`, `completed_at`); optional `status_filter`. |
| Per-domain history | `GET /api/v1/scans/history` | Unchanged; filter by `domain`. |
| Deduplicated hosts | `GET /api/v1/inventory/summary` | Latest row per host across recent **completed** scans; merges `asset_metadata` collection. |
| Metadata CRUD | `PUT /api/v1/assets/metadata`, `POST /api/v1/assets/metadata/bulk` | Upsert owner / environment / criticality by host. |
| Pipeline merge | `_run_scan_pipeline` | After discovery, overlays `asset_metadata` onto `ScanAsset` fields before TLS. |

**Config (`Settings`):** `MAX_BATCH_DOMAINS` (default 25), `MAX_CONCURRENT_SCANS` (default 3).

---

## 2. Frontend

| Surface | Behavior |
|---------|----------|
| **Overview** | “Portfolio batch scan” card: textarea (newline/comma-separated domains), client cap 25, `POST /scan/batch`, toast + link to Inventory Runs. |
| **Inventory Runs** | Loads `GET /scans/recent` (single request); columns include batch id, started/completed timestamps. |
| **Inventory Assets** | “Portfolio hosts (deduplicated)” table from `GET /inventory/summary` plus existing discovery feed. |

---

## 3. Phase 2 exit criteria

- [x] Batch API queues multiple domains with shared `batch_id` and per-job `scan_id`.
- [x] Concurrent pipelines respect `MAX_CONCURRENT_SCANS`.
- [x] Portfolio run list does not require N+1 `GET /results/{domain}` calls.
- [x] Deduplicated inventory + metadata APIs documented and wired in UI.
- [x] This document committed as the Phase 2 contract.

---

*Update when changing batch limits, sort order of `/scans/recent`, or inventory merge rules.*
# Phase 3 — Analysis depth (threat model, NIST mapping, simulation)

**Status:** Implemented in this branch.  
**Theme (PRD §11):** NIST/threat enrichment, quantum score what-if — **indicative**, not certification.

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| CBOM enrichment | `app/modules/threat_nist_mapping.py` → `enrich_cbom_component_dict` | Adds `threat_vector`, `nist_primary_recommendation`, `nist_summary`, `nist_reference_urls` to each component. |
| CBOM API | `GET /api/v1/cbom/per-app` | Returns enriched components (used by CBOM + Crypto Findings UIs). |
| Threat summary | `GET /api/v1/threat-model/summary` | Static vector definitions + **counts from latest completed scan** (legacy TLS, RSA mentions, hybrid signals). |
| NIST catalog | `GET /api/v1/threat-model/nist-catalog` | Static FIPS 203/204/205 + SP 800-208 URLs. |
| Score simulation | `POST /api/v1/quantum-score/simulate` | Heuristic delta on engine 0–100 score; returns `assumptions`, `note`, `nist_pqc_references`. |
| Export bundle | `GET /api/v1/reports/export-bundle` | Includes `threat_nist_context` pointer to publications. |

---

## 2. Frontend

| Page | Phase 3 behavior |
|------|------------------|
| **Crypto Findings** | Threat-model summary strip (scan-aware counts + vector reference). Table columns: **Threat** (Shor/Grover/HNDL), **NIST focus** (primary recommendation). Detail sheet: NIST summary text + outbound links. |
| **CBOM** | Already surfaces `threat_vector` + `nist_primary_recommendation` in the per-component table (unchanged). |
| **Cyber Rating** | What-if simulation shows **assumptions** applied and **NIST publication links** returned by the API. |

---

## 3. Phase 3 exit criteria

- [x] Enriched CBOM payload consumed in product UI (Findings + CBOM).
- [x] Threat model summary + NIST catalog reachable from Crypto Findings.
- [x] Simulation API response fully reflected in Cyber Rating (scores + qualifiers + refs).
- [x] Copy consistently states **heuristic / indicative** (not formal risk or compliance proof).

---

*Update when adding new threat vectors, changing `enrich_cbom_component_dict` output shape, or altering simulation math.*
# Phase 4 — Policy & integrations (governance)

**Status:** Implemented in this branch.  
**Theme (PRD §11):** Organization crypto policy, outbound integrations, export audit trail.

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| Org policy | `GET/PUT /api/v1/admin/policy` | Stored in MongoDB `org_policy` (`_id: default`). PUT is **admin-only**. |
| Integrations | `GET/PUT /api/v1/admin/integrations` | Webhook URLs (masked on GET); PUT **admin-only**. |
| Scan-complete hooks | `_notify_scan_complete_hooks` in `routes.py` | If `notify_on_scan_complete`: POST JSON to outbound URL (optional), `{text}` to Slack incoming webhook (optional), same JSON payload to Jira/automation URL (optional). |
| Export audit | `GET /api/v1/admin/exports/history` | Lists `export_audit` events. |
| Client export log | `POST /api/v1/admin/exports/log` | Records browser-side downloads (roadmap / threat JSON). Authenticated users. |
| Policy vs scan | `GET /api/v1/dashboard/policy-alignment` | Compares org `min_tls_version` + FS flag to latest completed scan `tls_results` (**indicative**). |
| Helpers | `app/utils/policy_alignment.py` | TLS version ranking + summary counts. |
| Slack POST | `post_slack_incoming_webhook` in `webhook_notify.py` | Slack-compatible `{"text": "..."}`. |

---

## 2. Frontend

| Area | Behavior |
|------|----------|
| **Policy & Standards** (`/policy`) | Loads/saves `min_tls_version`, `require_forward_secrecy`, `pqc_readiness_target` (KEM · sig), `policy_notes` without cross-field mix-ups. |
| **Admin** (`/admin`) | Tabs: policy, exports (bundle + roadmap + threat downloads), integrations; export audit table includes **actor** when logged via `POST /admin/exports/log`. |
| **Dashboard** | Fetches policy alignment in parallel with summary; shows amber/green strip when a completed scan exists with TLS endpoints. |

---

## 3. Phase 4 exit criteria

- [x] Org policy CRUD with role separation (read: authenticated; write: admin).
- [x] Integrations stored with masked previews; scan-complete notifications to outbound + optional Slack + Jira-style JSON endpoint.
- [x] Export bundle continues to write server-side audit rows; additional exports can be logged via `POST /admin/exports/log`.
- [x] Dashboard surfaces **indicative** policy-vs-scan gap counts (not compliance certification).

---

*Update when adding new policy fields, new webhook channels, or stricter RBAC.*
# Phase 5 — Migration execution (tasks, waivers, visibility)

**Status:** Implemented in this branch.  
**Theme (PRD):** Operationalize remediation: backlog tasks, waivers, admin seeding, dashboard visibility.

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| Migration snapshot | `GET /api/v1/dashboard/migration-snapshot` | Counts `open` / `in_progress` tasks and `pending` waivers for dashboard strips. |
| Tasks | `GET/POST/PATCH/DELETE /api/v1/migration/tasks` | CRUD for `migration_tasks` in MongoDB. Delete is **admin-only**. |
| List filters | `GET /migration/tasks?domain=&status_filter=` | Narrow task list by domain and status. |
| Seed from backlog | `POST /api/v1/migration/tasks/seed-from-backlog` | **Admin-only.** Builds tasks from `build_prioritized_backlog` for latest completed scan; body `domain` (optional), `limit` (1–80). |
| Waivers | `GET/POST/PATCH/DELETE /api/v1/migration/waivers` | Exception requests; approve/reject on PATCH is **admin-only**. |
| Waiver audit | `create_waiver` stores `created_by` | Submitter email from JWT user. |
| Roadmap (read) | `GET /api/v1/migration/roadmap` | Phased waves derived from scan (reporting input). |

---

## 2. Frontend

| Area | Behavior |
|------|----------|
| **Migration** (`/migration`) | Tabs: tasks (filters + Apply/Clear, admin seed with optional domain + max tasks), new task form, waivers list with **Submitted as** when `created_by` is set. |
| **Dashboard** | Fetches migration snapshot; shows **Migration queue** link to `/migration` when there is work. |

---

## 3. Phase 5 exit criteria

- [x] Authenticated users can list/create/update tasks and submit waivers.
- [x] Admins can delete tasks, seed from scan backlog (scoped domain + limit), approve/reject waivers, delete waivers.
- [x] Dashboard exposes aggregate migration workload (open/in-progress tasks, pending waivers).
- [x] Waiver records include who submitted (`created_by`).

---

*Update when adding task assignments, SLA fields, or Jira/ServiceNow sync.*
# Phase 6 — Stakeholder reporting (executive brief)

**Status:** Implemented in this branch.  
**Theme:** One-call portfolio rollup for demos, print/PDF, and leadership narrative — **not** a compliance product.

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| KPI helper | `_compute_dashboard_kpis_from_completed_scans` in `routes.py` | Shared math for `/dashboard/summary` and `/dashboard/executive-brief`. |
| Executive brief | `GET /api/v1/dashboard/executive-brief` | Auth required. Returns `generated_at`, `disclaimer`, `kpis`, `portfolio` (unique hosts + scan window size), `migration` counts, `policy` (targets + `summarize_tls_vs_policy` on latest scan), `domains` (up to 30 domains, latest scan each). |

---

## 2. Frontend

| Area | Behavior |
|------|----------|
| **Executive brief** (`/executive-brief`) | Loads brief; KPI grid; policy vs scan; domain table; **Print** and **JSON** download; logs `executive_brief_print` / `executive_brief_json` via `POST /admin/exports/log` when used. |
| **Nav** | Sidebar link **Executive brief**. |

---

## 3. Phase 6 exit criteria

- [x] Authenticated users can fetch a single JSON snapshot suitable for board-style narrative.
- [x] UI supports print (existing global print CSS hides chrome) and structured JSON export.
- [x] Export actions are auditable (best-effort client log).
- [x] Disclaimers match Phase 4 policy alignment (indicative / heuristic).

---

*Update when adding PDF server-side generation or scheduled email digests.*
# Phase 7 — Operational visibility

**Status:** Implemented in this branch.  
**Theme:** Give admins a quick read on datastore health, scan queue pressure, configured limits, and recent failures (NFR observability / ops console).

---

## 1. Backend

| Piece | Location | Role |
|-------|----------|------|
| Ops snapshot | `GET /api/v1/dashboard/ops-snapshot` | **`require_admin` only.** MongoDB `ping`, counts for `running` / `pending` scans, `completed` in last 24h, `failed` in last 7d, app name/version + scanner limits from `settings`, up to 12 most recent failed scans (truncated error text). |

---

## 2. Frontend

| Area | Behavior |
|------|----------|
| **Admin → Operations** tab | Visible only when `user.role === "Admin"`. Loads snapshot on tab select; cards for DB status, scan queue, limits, failure table with refresh. |

---

## 3. Phase 7 exit criteria

- [x] Admins can confirm Mongo connectivity without shell access.
- [x] Running/pending backlog and recent failure excerpts surface pipeline health.
- [x] Config caps (`MAX_CONCURRENT_SCANS`, batch/subdomain limits) visible for demo alignment with `.env`.

---

*Update when adding Prometheus metrics, external tool probes, or alert hooks.*

---

# Stage Output Contract (Stages 1-12)

**Status:** Implemented in this branch.  
**Theme:** Emit bounded, structured stage-complete telemetry for logs, WebSocket, and persisted scan stage records.

## 1. Configuration toggles

- `SCANNER_STAGE_VERBOSE_LOGS` (default `true`) — emit stage-complete structured logs.
- `SCANNER_STAGE_WS_SUMMARY` (default `true`) — broadcast `stage_complete` payload after each stage.
- `SCANNER_STAGE_DB_SUMMARY` (default `true`) — persist `summary` and `preview` into `scans.stages[]`.
- `SCANNER_STAGE_PREVIEW_LIMIT` (default `3`) — max preview items per stage payload.
- `SCANNER_STAGE_MESSAGE_MAX_LEN` (default `300`) — truncation limit for long text values.

## 2. Emitted payload shape

Each stage-complete payload includes:

- Core:
  - `scan_id`, `stage`, `status`, `duration_ms`, `request_count`
- Optional:
  - `error` (truncated)
- Structured:
  - `summary` (counts/flags)
  - `preview` (small, redacted/truncated sample)

## 3. Stage-specific summary keys

- Stage 1 `recon`: `subdomains`, `ip_hosts`, `dns_records`, `whois_present`, `zone_transfer_vulnerable`
- Stage 2 `network`: `ips_scanned`, `open_ports`, `services`
- Stage 3 `os_fingerprint`: `fingerprints`, `high_confidence`
- Stage 4 `tls_engine`: `tls_profiles`, `tls13_hosts`, `weak_proto_hosts`
- Stage 5 `crypto_analysis`: `findings_total`, `critical`, `high`, `hndl_hosts`
- Stage 6 `cdn_waf`: `cdn_hits`, `waf_hits`, `proxy_hits`
- Stage 7 `tech_fingerprint`: `tech_hits`, `unique_tech`
- Stage 8 `web_discovery`: `web_profiles`, `api_endpoints`, `forms`
- Stage 9 `hidden_discovery`: `hidden_paths`, `sensitive_files`, `admin_panels`
- Stage 10 `vuln_engine`: `vulns_total`, `critical`, `high`, `cve_refs`
- Stage 11 `correlation`: `graph_nodes`, `graph_edges`, `attack_paths`, `scored_assets`
- Stage 12 `reporting`: `cbom_components`, `recommendations`, `executive_summary_present`, `quantum_score_present`

## 4. Manual validation checklist

- [ ] Run one full custom scan with all 12 stages wired.
- [ ] Confirm 12 stage-complete lines in backend logs.
- [ ] Confirm WebSocket receives `stage_complete` per stage (bounded payload).
- [ ] Confirm Mongo `scans.stages[]` contains `summary` + `preview` (when DB summaries enabled).
- [ ] Toggle each setting (`*_VERBOSE_LOGS`, `*_WS_SUMMARY`, `*_DB_SUMMARY`) and verify expected suppression behavior.

## 5. Runtime 12-stage order

Expected runtime order in `_run_custom_scan_pipeline`:

1. `recon`
2. `network`
3. `os_fingerprint`
4. `tls_engine`
5. `crypto_analysis`
6. `cdn_waf`
7. `tech_fingerprint`
8. `web_discovery`
9. `hidden_discovery`
10. `vuln_engine`
11. `correlation`
12. `reporting`

