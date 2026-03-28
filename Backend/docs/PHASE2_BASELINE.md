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
