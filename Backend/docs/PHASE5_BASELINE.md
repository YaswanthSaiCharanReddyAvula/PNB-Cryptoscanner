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
