# TestSprite AI Testing Report (MCP)

---

## 1️⃣ Document Metadata

- **Project Name:** QuantumShield (PNB Crypto Scanner)
- **Date:** 2026-03-28 (testing started against Linux VM)
- **Prepared by:** TestSprite CLI + `testsprite_tests/run_backend_plan_local.py`
- **API under test:** `http://192.168.56.102:8000` (Linux; host-only IP from Windows per `testsprite_tests/tmp/config.json`)
- **Artifacts:**
  - `testsprite_tests/testsprite_backend_test_plan.json` — TC001–TC010
  - `testsprite_tests/run_backend_plan_local.py` — local HTTP smoke
  - `testsprite_tests/tmp/local_backend_smoke_report.json` — latest JSON results
  - `testsprite_tests/tmp/raw_report.md` — session notes

---

## 2️⃣ Requirement Validation Summary

### TestSprite cloud runner

| Phase | Status |
|-------|--------|
| `generateCodeAndExecute` | **Failed** — tunnel `read ECONNRESET` before tests ran (**0** cloud tests executed). |

### Local smoke (TC001–TC010) vs `http://192.168.56.102:8000`

| ID | Title | Status | HTTP |
|----|--------|--------|------|
| TC001 | POST `/api/v1/scan` | **Pass** | 202 |
| TC002 | POST `/api/v1/scan/batch` | **Fail** | **404** (route not exposed on this server build) |
| TC003 | GET `/api/v1/results/{domain}` | **Pass** | 200 |
| TC004 | GET `/api/v1/scans/history` | **Fail** | **404** (route not exposed) |
| TC005 | GET `/api/v1/scans/diff` | **Unclear** | 404 — OpenAPI on host did not list this path; may be missing route vs. valid 404 for missing scans |
| TC006 | GET `/api/v1/cbom/summary` | **Pass** | 200 |
| TC007 | GET `/api/v1/cbom/per-app` | **Pass** | 200 |
| TC008 | GET `/api/v1/cbom/charts` | **Pass** | 200 |
| TC009 | GET `/api/v1/crypto/security` | **Pass** | 200 |
| TC010 | GET `/api/v1/pqc/posture` | **Pass** | 200 |

**Deployment gap:** On the Linux host, `GET /openapi.json` did **not** include portfolio routes (`/scan/batch`, `/scans/history`, `/scans/diff`). Pull the latest branch, ensure `Backend/app/api/routes.py` contains those handlers, and restart **uvicorn** so TC002/TC004 match the test plan.

---

## 3️⃣ Coverage & Matching Metrics

| Metric | Value |
|--------|--------|
| Plan cases (TC001–TC010) | **10** |
| TestSprite cloud executed | **0** (tunnel error) |
| Local smoke pass (strict) | **9 / 11** checks (health + TC001–TC010); **TC002, TC004** failed |

---

## 4️⃣ Key Gaps / Risks

1. **TestSprite tunnel:** Retry when the network is stable; failures are environmental, not application assertions from the cloud runner.

2. **Linux VM API revision:** Redeploy so OpenAPI includes **POST `/api/v1/scan/batch`** and **GET `/api/v1/scans/history`** (and verify **GET `/api/v1/scans/diff`**). Until then, TC002/TC004 will not pass against this host.

3. **Re-run local smoke:**  
   `set TESTSPRITE_API_BASE=http://192.168.56.102:8000`  
   `python testsprite_tests/run_backend_plan_local.py`

4. **Health:** Current `/health` on the VM did not return the newer `mongodb` / `status` fields; optional restart after pulling latest `app/main.py` for consistency.
