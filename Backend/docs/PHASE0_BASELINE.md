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
