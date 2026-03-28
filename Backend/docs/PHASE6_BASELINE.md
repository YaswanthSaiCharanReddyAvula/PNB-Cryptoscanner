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
