#!/usr/bin/env python3
"""
Smoke-test QuantumShield Copilot via the real HTTP API.

Prerequisites:
  - Backend running, e.g.  uvicorn app.main:app --host 127.0.0.1 --port 8000
  - MongoDB reachable (same as normal app startup)

Usage:
  cd Backend
  python scripts/copilot_api_smoke.py

Optional:
  set API_BASE=http://127.0.0.1:8000/api/v1
"""

from __future__ import annotations

import json
import os
import sys

try:
    import httpx
except ImportError:
    print("Install dependencies: pip install httpx", file=sys.stderr)
    raise SystemExit(1)


def _base() -> str:
    return os.environ.get("API_BASE", "http://127.0.0.1:8000/api/v1").rstrip("/")


def login(client: httpx.Client, base: str) -> str:
    r = client.post(
        f"{base}/auth/login",
        json={"email": "scanner@example.com", "password": "pass123"},
    )
    r.raise_for_status()
    data = r.json()
    tok = data.get("access_token")
    if not tok:
        raise RuntimeError(f"Login missing access_token: {data!r}")
    return str(tok)


def copilot(
    client: httpx.Client,
    base: str,
    token: str,
    message: str,
    domain: str | None,
) -> httpx.Response:
    return client.post(
        f"{base}/ai/copilot/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": message, "domain": domain},
    )


def main() -> int:
    base = _base()
    fake_domain = "zzz-copilot-smoke-nonexistent.invalid"

    tests: list[tuple[str, dict]] = [
        (
            "Unknown domain in Domain field → no_completed_scan, no fake scores",
            {
                "message": "Summarize security posture for this domain.",
                "domain": fake_domain,
                "expect_error": "no_completed_scan",
                "reply_substrings": ("No records", "Overview"),
            },
        ),
        (
            "Hostname only in message (domain field blank) → same scope",
            {
                "message": f"What is the TLS posture for {fake_domain}?",
                "domain": None,
                "expect_error": "no_completed_scan",
                "reply_substrings": ("No records",),
            },
        ),
        (
            "Trivial greeting with no domain → may use latest scan (200 + reply only)",
            {
                "message": "hi",
                "domain": None,
                "expect_error": None,
                "reply_substrings": (),
            },
        ),
    ]

    print(f"API_BASE={base}\n")

    try:
        with httpx.Client(timeout=120.0) as client:
            token = login(client, base)
            print("Login OK (demo admin token).\n")

            passed = 0
            for title, cfg in tests:
                print(f"--- {title} ---")
                r = copilot(client, base, token, cfg["message"], cfg["domain"])
                print(f"  HTTP {r.status_code}")
                if r.status_code != 200:
                    print(r.text[:500])
                    print("  FAIL\n")
                    continue
                data = r.json()
                ctx = data.get("context_used") or {}
                reply = str(data.get("reply") or "")

                exp = cfg["expect_error"]
                if exp is not None:
                    err = ctx.get("error")
                    if err != exp:
                        print(f"  context_used.error: {err!r} (expected {exp!r})")
                        print("  FAIL\n")
                        continue
                    missing = [s for s in cfg["reply_substrings"] if s not in reply]
                    if missing:
                        print(f"  reply missing substring(s): {missing!r}")
                        print(json.dumps({"reply": reply[:800]}, indent=2)[:1200])
                        print("  FAIL\n")
                        continue
                    print(f"  context_used: {json.dumps(ctx, indent=2)[:600]}")
                    print(f"  reply (excerpt): {reply[:320]}…")
                    print("  PASS\n")
                    passed += 1
                else:
                    if not reply.strip():
                        print("  empty reply")
                        print("  FAIL\n")
                        continue
                    print(f"  reply (excerpt): {reply[:400]}…")
                    print("  PASS\n")
                    passed += 1

            print(f"Done: {passed}/{len(tests)} passed.")
            return 0 if passed == len(tests) else 1

    except httpx.ConnectError as e:
        print(f"Cannot connect to {base}: {e}", file=sys.stderr)
        print(
            "Start the API first: uvicorn app.main:app --host 127.0.0.1 --port 8000",
            file=sys.stderr,
        )
        return 2
    except httpx.HTTPStatusError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        print(getattr(e.response, "text", "")[:800], file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
