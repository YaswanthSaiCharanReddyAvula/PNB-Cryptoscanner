"""
QuantumShield — OS Fingerprint Engine (Stage 4)

Passive OS detection from SSH banners, HTTP headers, TTL hints, and
container indicators.  No raw-socket crafting — userspace only.

HTTP Server header evidence is downgraded when CDN/WAF is detected
upstream (CDNWAFEngine at Stage 3) to prevent edge-infrastructure
misattribution.
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

CONTAINER_HOSTNAME_RE = re.compile(
    r"^[0-9a-f]{12}$|[0-9a-f]{8}-[0-9a-f]{4}-|deployment-|statefulset-|daemonset-"
)

# Weights for different evidence sources (origin context).
# When a CDN/WAF is detected, HTTP Server header weight is reduced
# to EDGE_HTTP_SERVER_WEIGHT because the header likely reflects
# edge infrastructure rather than the origin server.
OS_EVIDENCE_WEIGHTS = {
    "ssh_banner":       0.9,
    "http_server_os":   0.7,
    "hostname_pattern": 0.3,
}

EDGE_HTTP_SERVER_WEIGHT = 0.15


class OSFingerprintEngine(ScanStage):
    name = "os_fingerprint"
    order = 4
    timeout_seconds = 45
    max_retries = 1
    criticality = StageCriticality.IMPORTANT
    required_fields = ["services"]
    writes_fields = ["os_fingerprints"]
    merge_strategy = MergeStrategy.OVERWRITE

    async def execute(self, ctx: ScanContext) -> StageResult:
        fps: list[dict] = []
        hosts_done: set[str] = set()

        # Build CDN/WAF lookup from upstream CDNWAFEngine results
        cdn_waf_hosts = self._build_cdn_waf_lookup(ctx)

        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            host = s.get("host", "")
            if not host or host in hosts_done:
                continue
            hosts_done.add(host)

            votes: dict[str, float] = {}
            evidence: list[str] = []
            os_version: Optional[str] = None
            container = False
            container_ev: list[str] = []
            host_behind_edge = host in cdn_waf_hosts

            host_services = [
                sv if isinstance(sv, dict) else {}
                for sv in (ctx.services or [])
                if (sv if isinstance(sv, dict) else {}).get("host") == host
            ]

            for sv in host_services:
                banner = sv.get("raw_banner") or ""
                sname = sv.get("service_name") or ""

                # SSH banners are direct origin evidence — CDN does not proxy SSH
                if "ssh" in sname.lower() or sv.get("port") == 22:
                    family, version = self._parse_ssh(banner)
                    if family:
                        votes[family] = votes.get(family, 0) + OS_EVIDENCE_WEIGHTS["ssh_banner"]
                        os_version = version
                        evidence.append("ssh_banner")

                # HTTP Server header — downgrade weight when behind CDN/WAF
                if sv.get("port") in (80, 443, 8080, 8443) or sname.lower() in ("http", "https"):
                    family, version = self._parse_server(banner)
                    if family:
                        weight = (
                            EDGE_HTTP_SERVER_WEIGHT
                            if host_behind_edge
                            else OS_EVIDENCE_WEIGHTS["http_server_os"]
                        )
                        votes[family] = votes.get(family, 0) + weight
                        if not os_version:
                            os_version = version
                        evidence.append(
                            "http_server_os_edge" if host_behind_edge else "http_server_os"
                        )

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
                container_likely=container,
                container_evidence=container_ev,
                evidence_sources=evidence,
            ).model_dump())

        return StageResult(
            status="completed",
            data={"os_fingerprints": fps},
        )

    # ── CDN/WAF correlation ───────────────────────────────────────────

    @staticmethod
    def _build_cdn_waf_lookup(ctx: ScanContext) -> set[str]:
        """Return set of hostnames that are behind a CDN, WAF, or reverse proxy."""
        edge_hosts: set[str] = set()
        for intel in (ctx.cdn_waf_intel or []):
            i = intel if isinstance(intel, dict) else {}
            host = i.get("host", "")
            if not host:
                continue
            if i.get("cdn_provider") or i.get("waf_detected") or i.get("reverse_proxy"):
                edge_hosts.add(host)
        return edge_hosts

    # ── Banner parsing ────────────────────────────────────────────────

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
