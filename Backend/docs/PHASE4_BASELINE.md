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
