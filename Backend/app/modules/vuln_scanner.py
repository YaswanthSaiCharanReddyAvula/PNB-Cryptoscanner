"""
Optional Nuclei subprocess: time-bounded HTTP/TLS/misconfig templates on web-facing hosts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from typing import List
from urllib.parse import urlparse

from app.config import settings
from app.db.models import ActiveVulnFinding, DiscoveredAsset
from app.utils.asset_type import classify_asset_ports

logger = logging.getLogger(__name__)


def _urls_for_asset(asset: DiscoveredAsset) -> List[str]:
    host = (asset.subdomain or "").strip()
    if not host:
        return []
    ports = set(int(p) for p in (asset.open_ports or []) if p is not None)
    urls: List[str] = []
    if 443 in ports:
        urls.append(f"https://{host}")
    if 80 in ports:
        urls.append(f"http://{host}")
    if not urls and (8080 in ports or 8443 in ports):
        scheme = "https" if 8443 in ports else "http"
        port = 8443 if 8443 in ports else 8080
        urls.append(f"{scheme}://{host}:{port}")
    return urls


def _parse_nuclei_line(line: str) -> ActiveVulnFinding | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    info = obj.get("info") or {}
    if isinstance(info, str):
        info = {}
    sev = (info.get("severity") or "info").lower()
    name = str(info.get("name") or info.get("description") or "Finding")[:500]
    url = obj.get("matched") or obj.get("url")
    host = str(obj.get("host") or "").strip()
    if not host and url:
        try:
            host = (urlparse(str(url)).hostname or "").strip()
        except Exception:
            host = ""
    if not host:
        mat = str(obj.get("matched-at") or "").strip()
        if mat.startswith("http"):
            try:
                host = (urlparse(mat).hostname or "").strip()
            except Exception:
                host = ""
        elif mat:
            host = mat.split("/")[0].split(":")[0]
    if url is not None:
        url = str(url)[:2048]
    tid = obj.get("template-id") or obj.get("template_id")
    if tid is not None:
        tid = str(tid)[:256]
    matcher = obj.get("matcher-name") or obj.get("matcher_name")
    if matcher is not None:
        matcher = str(matcher)[:128]
    return ActiveVulnFinding(
        source="nuclei",
        template_id=tid,
        name=name,
        severity=sev if sev in ("info", "low", "medium", "high", "critical") else "info",
        host=host[:256],
        url=url,
        matcher_name=matcher,
    )


async def run_nuclei_scan(
    assets: List[DiscoveredAsset],
    execution_time_limit_seconds: int | None,
) -> List[ActiveVulnFinding]:
    if not settings.ENABLE_NUCLEI:
        return []

    binary = settings.NUCLEI_BINARY or "nuclei"
    if not shutil.which(binary):
        logger.warning("Nuclei not found in PATH (%s); skipping active vuln scan.", binary)
        return []

    webish = [
        a
        for a in assets
        if classify_asset_ports(a.open_ports or []) == "web_app"
    ]
    max_h = max(1, int(settings.NUCLEI_MAX_HOSTS))
    webish = webish[:max_h]

    all_urls: List[str] = []
    for a in webish:
        all_urls.extend(_urls_for_asset(a))
    all_urls = list(dict.fromkeys(all_urls))
    if not all_urls:
        return []

    cap = execution_time_limit_seconds
    if cap is None or cap <= 0:
        cap = int(settings.SCAN_TIMEOUT)
    process_timeout = float(min(cap, max(30, cap)))

    tags = (settings.NUCLEI_TAGS or "tls,misconfig,technologies").strip()
    tmpl_timeout = max(3, int(settings.NUCLEI_TEMPLATE_TIMEOUT_SECONDS))

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
            newline="\n",
        ) as f:
            for u in all_urls:
                f.write(u + "\n")
            tmp_path = f.name

        cmd = [
            binary,
            "-l",
            tmp_path,
            "-tags",
            tags,
            "-jsonl",
            "-silent",
            "-duc",
            "-timeout",
            str(tmpl_timeout),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=process_timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("Nuclei killed after %.0fs timeout", process_timeout)
            return []

        if stderr:
            err_preview = stderr.decode(errors="replace")[:400]
            if proc.returncode not in (0, None) and err_preview.strip():
                logger.debug("nuclei stderr: %s", err_preview)

        out: List[ActiveVulnFinding] = []
        text = stdout.decode(errors="replace")
        for line in text.splitlines():
            finding = _parse_nuclei_line(line)
            if finding:
                out.append(finding)
        return out
    except FileNotFoundError:
        logger.warning("Nuclei binary not executable: %s", binary)
        return []
    except Exception as exc:
        logger.warning("Nuclei scan failed: %s", exc)
        return []
    finally:
        if tmp_path and os.path.isfile(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
