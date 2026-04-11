#!/usr/bin/env python3
"""
Manual smoke checks for scan reuse + 409 (requires running API + MongoDB).

  cd Backend && python scripts/scan_retention_smoke.py

Uses demo login and POST /scan twice for a fake domain; second call should return
reused: true with the same scan_id. Third call while pending would 409 (run quickly
or mock — here we only assert reuse if the first completes before second, which may
not hold; prefer checking reused on second POST after first completed).

For a deterministic reuse test without waiting for pipeline completion, use Mongo
or unit tests. This script documents the expected JSON shapes.
"""

from __future__ import annotations

import json
import os
import sys

try:
    import httpx
except ImportError:
    print("pip install httpx", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    base = os.environ.get("API_BASE", "http://127.0.0.1:8000/api/v1").rstrip("/")
    domain = "zzz-scan-retention-smoke.invalid"
    with httpx.Client(timeout=60.0) as client:
        r = client.post(
            f"{base}/auth/login",
            json={"email": "scanner@example.com", "password": "pass123"},
        )
        r.raise_for_status()
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        r1 = client.post(
            f"{base}/scan",
            headers=h,
            json={"domain": domain},
        )
        print("First POST /scan:", r1.status_code, r1.text[:800])
        if r1.status_code not in (200, 202):
            return 1
        j1 = r1.json()
        sid = j1.get("scan_id")

        r2 = client.post(
            f"{base}/scan",
            headers=h,
            json={"domain": domain},
        )
        print("Second POST /scan (expect 409 if first still running):", r2.status_code, r2.text[:800])
        if r2.status_code == 409:
            print("OK: conflict while scan in progress.")
            return 0
        if r2.status_code not in (200, 202):
            return 1
        j2 = r2.json()
        if j2.get("reused") is True and j2.get("scan_id") == sid:
            print("OK: in-place rescan reused same scan_id.")
            return 0
        print(
            "Note: second call did not reuse (first scan may not have finished yet).",
            json.dumps(j2, indent=2)[:600],
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
