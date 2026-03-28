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
