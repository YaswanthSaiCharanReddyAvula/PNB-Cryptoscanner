"""
QuantumShield — OS Fingerprint Engine (Stage 3)

Passive OS detection from SSH banners, HTTP headers, TTL hints, and
container indicators.  No raw-socket crafting — userspace only.
"""

from __future__ import annotations

import re
from typing import Optional

from app.scanner.models import OSFingerprint, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

SSH_OS_MAP: list[tuple[str, str, str]] = [
    (r"Ubuntu[- ](\S+)",              "Linux",   "Ubuntu {0}"),
    (r"Debian[- ](\S+)",              "Linux",   "Debian {0}"),
    (r"FreeBSD[- ](\S+)",             "FreeBSD", "FreeBSD {0}"),
    (r"CentOS",                       "Linux",   "CentOS"),
    (r"Red Hat|RHEL",                 "Linux",   "Red Hat Enterprise Linux"),
    (r"Fedora",                       "Linux",   "Fedora"),
    (r"SUSE|openSUSE",               "Linux",   "SUSE"),
    (r"Arch",                         "Linux",   "Arch Linux"),
    (r"Alpine",                       "Linux",   "Alpine Linux"),
    (r"Raspbian",                     "Linux",   "Raspbian"),
    # Generic fallbacks (must be last — distro-specific matches take priority)
    (r"OpenSSH[_-](\S+)",             "Linux",   "Linux (OpenSSH {0})"),
    (r"dropbear[_-](\S+)",            "Linux",   "Linux (Dropbear {0})"),
]

SERVER_OS_MAP: list[tuple[str, str, str]] = [
    (r"Apache/[\d.]+ \(Ubuntu\)",     "Linux",   "Ubuntu"),
    (r"Apache/[\d.]+ \(Debian\)",     "Linux",   "Debian"),
    (r"Apache/[\d.]+ \(CentOS\)",     "Linux",   "CentOS"),
    (r"Apache/[\d.]+ \(Win\w+\)",     "Windows", "Windows"),
    (r"Microsoft-IIS/([\d.]+)",       "Windows", "Windows Server (IIS {0})"),
    (r"nginx/[\d.]+ \(Ubuntu\)",      "Linux",   "Ubuntu"),
    (r"nginx",                        "Linux",   "Linux (nginx)"),
    (r"Apache",                       "Linux",   "Linux (Apache)"),
]

RUNTIME_PATTERNS: list[tuple[str, str]] = [
    (r"PHP/([\d.]+)",          "PHP {0}"),
    (r"Express",               "Node.js (Express)"),
    (r"ASP\.NET",              ".NET"),
    (r"Werkzeug|gunicorn|uvicorn", "Python"),
    (r"Servlet",               "Java (Servlet)"),
]

CONTAINER_HOSTNAME_RE = re.compile(
    r"^[0-9a-f]{12}$|[0-9a-f]{8}-[0-9a-f]{4}-|deployment-|statefulset-|daemonset-"
)

OS_EVIDENCE_WEIGHTS = {
    "ssh_banner":       0.9,
    "http_server_os":   0.7,
    "x_powered_by":     0.5,
    "cookie_name":      0.3,
    "ttl_guess":        0.2,
    "hostname_pattern": 0.3,
}


class OSFingerprintEngine(ScanStage):
    name = "os_fingerprint"
    order = 3
    timeout_seconds = 45
    max_retries = 1
    criticality = StageCriticality.IMPORTANT
    required_fields = ["services"]
    writes_fields = ["os_fingerprints"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        fps: list[dict] = []
        hosts_done: set[str] = set()

        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            host = s.get("host", "")
            if not host or host in hosts_done:
                continue
            hosts_done.add(host)

            votes: dict[str, float] = {}
            evidence: list[str] = []
            os_version: Optional[str] = None
            runtime: Optional[str] = None
            container = False
            container_ev: list[str] = []

            host_services = [
                sv if isinstance(sv, dict) else {}
                for sv in (ctx.services or [])
                if (sv if isinstance(sv, dict) else {}).get("host") == host
            ]

            for sv in host_services:
                banner = sv.get("raw_banner") or ""
                sname = sv.get("service_name") or ""

                if "ssh" in sname.lower() or sv.get("port") == 22:
                    family, version = self._parse_ssh(banner)
                    if family:
                        votes[family] = votes.get(family, 0) + OS_EVIDENCE_WEIGHTS["ssh_banner"]
                        os_version = version
                        evidence.append("ssh_banner")

                if sv.get("port") in (80, 443, 8080, 8443) or sname.lower() in ("http", "https"):
                    family, version = self._parse_server(banner)
                    if family:
                        votes[family] = votes.get(family, 0) + OS_EVIDENCE_WEIGHTS["http_server_os"]
                        if not os_version:
                            os_version = version
                        evidence.append("http_server_os")

                    rt = self._parse_runtime(banner)
                    if rt:
                        runtime = rt
                        evidence.append("x_powered_by")

            if CONTAINER_HOSTNAME_RE.search(host):
                container = True
                container_ev.append(f"hostname pattern: {host}")
                evidence.append("hostname_pattern")

            best_family = max(votes, key=votes.get) if votes else None
            total_weight = sum(votes.values())
            conf = "high" if total_weight >= 1.2 else "medium" if total_weight >= 0.6 else "low"

            fps.append(OSFingerprint(
                host=host,
                os_family=best_family,
                os_version=os_version,
                os_confidence=conf,
                runtime=runtime,
                container_likely=container,
                container_evidence=container_ev,
                evidence_sources=evidence,
            ).model_dump())

        return StageResult(
            status="completed",
            data={"os_fingerprints": fps},
        )

    @staticmethod
    def _parse_ssh(banner: str):
        for pattern, family, ver_tpl in SSH_OS_MAP:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                ver = ver_tpl.format(*m.groups()) if m.groups() else ver_tpl
                return family, ver
        return None, None

    @staticmethod
    def _parse_server(banner: str):
        for pattern, family, ver_tpl in SERVER_OS_MAP:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                ver = ver_tpl.format(*m.groups()) if m.groups() else ver_tpl
                return family, ver
        return None, None

    @staticmethod
    def _parse_runtime(banner: str) -> Optional[str]:
        for pattern, tpl in RUNTIME_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return tpl.format(*m.groups()) if m.groups() else tpl
        return None
