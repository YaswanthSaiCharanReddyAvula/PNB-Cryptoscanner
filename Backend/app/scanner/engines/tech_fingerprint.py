"""
QuantumShield — Technology Fingerprint Engine (Stage 7)

Wappalyzer-style detection of web servers, languages, frameworks,
CMS, JS libraries, and analytics from HTTP responses.  No external
tools — pure httpx + regex.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

import httpx

from app.scanner.models import StageResult, TechFingerprint
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

COOKIE_RUNTIME_MAP: dict[str, tuple[str, str]] = {
    "JSESSIONID":         ("language", "Java"),
    "PHPSESSID":          ("language", "PHP"),
    "ASP.NET_SessionId":  ("language", ".NET"),
    "connect.sid":        ("framework", "Express/Node.js"),
    "laravel_session":    ("framework", "Laravel"),
    "csrftoken":          ("framework", "Django"),
    "_rails_session":     ("framework", "Ruby on Rails"),
}

ERROR_PAGE_SIGS: list[tuple[str, str, str]] = [
    (r"Whitelabel Error Page",         "framework", "Spring Boot"),
    (r"Django Version:",               "framework", "Django"),
    (r"Traceback \(most recent call",  "language",  "Python"),
    (r"<b>Fatal error</b>.*PHP",       "language",  "PHP"),
    (r"Microsoft .NET Framework.*Error", "language", ".NET"),
    (r"Ruby on Rails",                 "framework", "Ruby on Rails"),
    (r"Express.*Error",                "framework", "Express"),
]

_sig_cache: Optional[list[dict]] = None


def _load_signatures() -> list[dict]:
    global _sig_cache
    if _sig_cache is not None:
        return _sig_cache
    path = _DATA_DIR / "tech_signatures.json"
    if path.is_file():
        try:
            _sig_cache = json.loads(path.read_text(encoding="utf-8"))
            return _sig_cache
        except Exception:
            logger.warning("Failed to load tech_signatures.json", exc_info=True)
    _sig_cache = []
    return _sig_cache


class TechFingerprintEngine(ScanStage):
    name = "tech_fingerprint"
    order = 7
    timeout_seconds = 45
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["subdomains"]
    writes_fields = ["tech_fingerprints"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        results: list[dict] = []
        request_count = 0
        sigs = _load_signatures()

        web_hosts = self._web_hosts(ctx)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10.0
        ) as client:
            for host in web_hosts:
                try:
                    async with ctx.throttle.acquire("http_probe"):
                        fps, reqs = await self._fingerprint_host(client, host, sigs, ctx)
                        results.extend(fps)
                        request_count += reqs
                except Exception:
                    logger.warning("Tech FP failed for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"tech_fingerprints": results},
            request_count=request_count,
        )

    @staticmethod
    def _web_hosts(ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else (svc.model_dump() if hasattr(svc, 'model_dump') else {})
            if s.get("protocol_category") == "web" or s.get("port") in (80, 443, 8080, 8443):
                h = s.get("host", "")
                if h and h not in hosts:
                    hosts.append(h)
        if not hosts:
            hosts = list(ctx.subdomains or [])
        return hosts

    async def _fingerprint_host(self, client, host, sigs, ctx):
        fps: list[dict] = []
        reqs = 0

        try:
            resp = await client.get(f"https://{host}/")
            reqs += 1
        except httpx.ConnectError:
            try:
                resp = await client.get(f"http://{host}/")
                reqs += 1
            except Exception:
                return fps, reqs
        except Exception:
            return fps, reqs

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:65536]
        hdr_str = str(hdrs)

        for sig in sigs:
            for match_rule in sig.get("matches", []):
                mtype = match_rule.get("type", "")
                pat = match_rule.get("pattern", "")
                if not pat:
                    continue
                source = hdr_str if mtype == "header" else body if mtype in ("html", "script") else str(resp.cookies)
                m = re.search(pat, source, re.IGNORECASE)
                if m:
                    ver = None
                    vg = match_rule.get("version_group")
                    if vg is not None and m.lastindex and vg <= m.lastindex:
                        ver = m.group(vg)
                    cpe = None
                    cpe_tpl = sig.get("cpe_template")
                    if cpe_tpl and ver:
                        cpe = cpe_tpl.replace("{version}", ver)
                    fps.append(TechFingerprint(
                        host=host,
                        category=sig.get("category", "unknown"),
                        name=sig.get("name", "unknown"),
                        version=ver,
                        confidence=match_rule.get("confidence", "medium"),
                        evidence=f"{mtype} match: {pat[:60]}",
                        cpe=cpe,
                    ).model_dump())
                    break

        for cookie_name, (cat, tech) in COOKIE_RUNTIME_MAP.items():
            if cookie_name.lower() in str(resp.cookies).lower():
                fps.append(TechFingerprint(
                    host=host, category=cat, name=tech,
                    confidence="medium", evidence=f"cookie {cookie_name}",
                ).model_dump())

        try:
            async with ctx.throttle.acquire("http_probe"):
                err_resp = await client.get(f"https://{host}/qshield_404_probe_xyz")
                reqs += 1
                err_body = err_resp.text[:4000]
                for pat, cat, tech in ERROR_PAGE_SIGS:
                    if re.search(pat, err_body, re.IGNORECASE):
                        fps.append(TechFingerprint(
                            host=host, category=cat, name=tech,
                            confidence="medium", evidence=f"error page: {pat[:40]}",
                        ).model_dump())
                        break
        except Exception:
            pass

        try:
            async with ctx.throttle.acquire("http_probe"):
                fav_resp = await client.get(f"https://{host}/favicon.ico")
                reqs += 1
                if fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                    fav_hash = hashlib.md5(fav_resp.content).hexdigest()
                    fps.append(TechFingerprint(
                        host=host, category="favicon", name=f"hash:{fav_hash}",
                        confidence="low", evidence=f"favicon MD5 {fav_hash}",
                    ).model_dump())
        except Exception:
            pass

        return fps, reqs
