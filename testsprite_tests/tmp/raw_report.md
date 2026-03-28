# Latest test run — after Linux backend restart

**Endpoint:** `http://192.168.56.102:8000`

## OpenAPI
Portfolio routes present: `/api/v1/scan/batch`, `/api/v1/scans/history`, `/api/v1/scans/diff`.

## Local smoke (`run_backend_plan_local.py`)

| Case | Result | Notes |
|------|--------|--------|
| HEALTH | Pass | `mongodb: connected` |
| TC001–TC007 | Pass | 202/200 as expected |
| TC008 | **Fail** | `GET /cbom/charts` returned **500** — caused by Mongo `cbom_report: null` (`.get("cbom_report", {})` still returns `None` when key exists). **Fixed in repo** (`routes.py`: use `(scan.get("cbom_report") or {})`). Redeploy backend and re-run smoke. |
| TC009–TC010 | Pass | |

## TestSprite cloud
Not re-run in this session (tunnel often unstable); use `npx @testsprite/testsprite-mcp generateCodeAndExecute` when ready.
