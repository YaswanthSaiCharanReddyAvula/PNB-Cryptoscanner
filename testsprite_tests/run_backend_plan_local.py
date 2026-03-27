"""
Local smoke run for testsprite_backend_test_plan.json (TC001–TC010).
Does not replace TestSprite cloud; use when tunnel to testsprite.com fails.

If the API runs on a Linux machine (e.g. Kali VM) and you test from Windows, point at the
VM’s LAN IP — not localhost on Windows:

  set TESTSPRITE_API_BASE=http://192.168.56.102:8000
  python testsprite_tests/run_backend_plan_local.py

Same host as the backend (Linux):

  python testsprite_tests/run_backend_plan_local.py
  # default http://127.0.0.1:8000 is correct
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

# Default: same machine as this script. For Windows → Linux VM API, set TESTSPRITE_API_BASE.
BASE = os.environ.get("TESTSPRITE_API_BASE", "http://127.0.0.1:8000").rstrip("/")
API = f"{BASE}/api/v1"
TIMEOUT = 60.0


def main() -> int:
    results: list[dict] = []
    with httpx.Client(timeout=TIMEOUT) as client:
        # Health
        r = client.get(f"{BASE}/health")
        if r.headers.get("content-type", "").startswith("application/json"):
            hbody = r.json()
            hnote = str(hbody)[:500]
        else:
            hnote = r.text[:500]
        results.append(
            {
                "id": "HEALTH",
                "path": "/health",
                "status": r.status_code,
                "ok": r.status_code == 200,
                "note": hnote,
            }
        )

        # TC001
        r = client.post(f"{API}/scan", json={"domain": "example.com", "include_subdomains": False})
        results.append(
            {
                "id": "TC001",
                "path": "POST /scan",
                "status": r.status_code,
                "ok": r.status_code in (202, 503),
                "note": "expect 202 when Mongo up, 503 when DB unavailable",
            }
        )

        # TC002
        r = client.post(
            f"{API}/scan/batch",
            json={"domains": ["example.org", "example.net"], "include_subdomains": False},
        )
        results.append(
            {
                "id": "TC002",
                "path": "POST /scan/batch",
                "status": r.status_code,
                "ok": r.status_code in (202, 503),
                "note": "expect 202 when Mongo up",
            }
        )

        # TC003
        r = client.get(f"{API}/results/example.com")
        results.append(
            {
                "id": "TC003",
                "path": "GET /results/{domain}",
                "status": r.status_code,
                "ok": r.status_code in (200, 404, 503),
                "note": "404 no scan; 503 no Mongo",
            }
        )

        # TC004
        r = client.get(f"{API}/scans/history", params={"domain": "example.com"})
        results.append(
            {
                "id": "TC004",
                "path": "GET /scans/history",
                "status": r.status_code,
                "ok": r.status_code in (200, 503),
            }
        )

        # TC005 (expect 404 without real scan ids)
        r = client.get(
            f"{API}/scans/diff",
            params={
                "domain": "example.com",
                "from_scan_id": "deadbeef",
                "to_scan_id": "cafebabe",
            },
        )
        results.append(
            {
                "id": "TC005",
                "path": "GET /scans/diff",
                "status": r.status_code,
                "ok": r.status_code in (404, 503),
                "note": "404 when scans missing",
            }
        )

        # TC006–TC008
        for tc, path in [
            ("TC006", "/cbom/summary"),
            ("TC007", "/cbom/per-app"),
            ("TC008", "/cbom/charts"),
        ]:
            r = client.get(f"{API}{path}")
            results.append(
                {
                    "id": tc,
                    "path": f"GET {path}",
                    "status": r.status_code,
                    "ok": r.status_code in (200, 503),
                }
            )

        # TC009
        r = client.get(f"{API}/crypto/security")
        results.append(
            {
                "id": "TC009",
                "path": "GET /crypto/security",
                "status": r.status_code,
                "ok": r.status_code in (200, 503),
            }
        )

        # TC010
        r = client.get(f"{API}/pqc/posture")
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        posture_ok = r.status_code == 200 and isinstance(j, dict) and "elite_count" in j
        results.append(
            {
                "id": "TC010",
                "path": "GET /pqc/posture",
                "status": r.status_code,
                "ok": r.status_code in (200, 503) and (r.status_code == 503 or posture_ok),
                "note": "200 with posture object when Mongo+scan; empty object if no scan",
            }
        )

    out_path = Path(__file__).resolve().parent / "tmp" / "local_backend_smoke_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "base_url": BASE,
        "passed": sum(1 for x in results if x["ok"]),
        "total": len(results),
        "cases": results,
    }
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if all(x["ok"] for x in results if x["id"].startswith("TC")) else 1


if __name__ == "__main__":
    sys.exit(main())
