# TestSprite raw notes — latest run

**Backend:** Linux VM at `http://192.168.56.102:8000` (reachable from Windows).

## TestSprite cloud (`npx @testsprite/testsprite-mcp generateCodeAndExecute`)

- **Result:** Failed before test dispatch.
- **Error:** `read ECONNRESET` on tunnel to `tun.testsprite.com` (after tunnel started).
- **Mitigation:** Stable network; retry without VPN; firewall allowing long-lived HTTPS to testsprite.

## Local smoke (`python testsprite_tests/run_backend_plan_local.py`)

`TESTSPRITE_API_BASE=http://192.168.56.102:8000`

| ID | Result | HTTP | Notes |
|----|--------|------|--------|
| HEALTH | Pass | 200 | |
| TC001 | Pass | 202 | POST `/api/v1/scan` |
| TC002 | **Fail** | **404** | `POST /api/v1/scan/batch` — **not in server OpenAPI** (deploy latest `routes.py` + restart uvicorn) |
| TC003 | Pass | 200 | GET `/api/v1/results/example.com` |
| TC004 | **Fail** | **404** | `GET /api/v1/scans/history` — **not in server OpenAPI** |
| TC005 | Pass (ambiguous) | 404 | `GET /api/v1/scans/diff` also **not listed** in OpenAPI; 404 may be “no route” not “scans not found” |
| TC006–TC010 | Pass | 200 | CBOM + crypto + PQC |

**OpenAPI on this Linux host** included e.g. `/api/v1/migration/roadmap`, `/api/v1/reports/export-bundle`, but **did not** include `/api/v1/scan/batch`, `/api/v1/scans/history`, `/api/v1/scans/diff`. Align the VM with the current branch and redeploy.

Machine-readable: `testsprite_tests/tmp/local_backend_smoke_report.json`
