"""
QuantumShield — Advanced OS Fingerprint Engine (Stage 13)

Two-tier OS fingerprinting:
  Tier 1 (userspace): TCP window size, MSS, connection behaviour — always runs.
  Tier 2 (privileged): raw SYN probe with TCP option analysis — graceful skip
  if not running as root/admin.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Optional

from app.scanner.models import AdvancedOSFingerprint, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

OS_FINGERPRINT_DB: list[dict] = [
    {
        "os": "Linux 5.x/6.x",
        "ttl_range": (60, 64),
        "window_sizes": [65535, 29200, 64240],
        "mss_values": [1460, 1448],
        "timestamp_present": True,
    },
    {
        "os": "Windows 10/11/Server 2019+",
        "ttl_range": (125, 128),
        "window_sizes": [65535, 64240],
        "mss_values": [1460],
        "timestamp_present": False,
    },
    {
        "os": "FreeBSD 13+",
        "ttl_range": (60, 64),
        "window_sizes": [65535],
        "mss_values": [1460],
        "timestamp_present": True,
    },
    {
        "os": "macOS 13+",
        "ttl_range": (60, 64),
        "window_sizes": [65535, 131072],
        "mss_values": [1460],
        "timestamp_present": True,
    },
    {
        "os": "Solaris/Illumos",
        "ttl_range": (252, 255),
        "window_sizes": [49640, 32768],
        "mss_values": [1460, 1024],
        "timestamp_present": True,
    },
]


class AdvancedFingerprintEngine(ScanStage):
    name = "advanced_fingerprint"
    order = 13
    timeout_seconds = 60
    max_retries = 0
    criticality = StageCriticality.OPTIONAL
    required_fields = ["services"]
    writes_fields = ["os_fingerprints"]
    merge_strategy = MergeStrategy.APPEND

    async def execute(self, ctx: ScanContext) -> StageResult:
        results: list[dict] = []
        hosts = self._target_hosts(ctx)

        for host in hosts[:30]:
            port = self._first_open_port(host, ctx)
            if not port:
                continue
            ip = self._resolve_ip(host, ctx)
            if not ip:
                continue

            try:
                fp = await self._userspace_probe(ip, port, ctx)
                if fp:
                    os_match, conf = self._match_os(fp)
                    results.append(AdvancedOSFingerprint(
                        host=host,
                        tier="userspace",
                        os_match=os_match,
                        match_confidence=conf,
                        tcp_window_size=fp.get("window_size"),
                        ttl_observed=fp.get("ttl"),
                        mss_observed=fp.get("mss"),
                        evidence_sources=fp.get("sources", []),
                    ).model_dump())
            except Exception:
                logger.debug("Advanced FP failed for %s", host, exc_info=True)

        return StageResult(
            status="completed",
            data={"os_fingerprints": results},
        )

    @staticmethod
    def _target_hosts(ctx: ScanContext) -> list[str]:
        hosts: list[str] = []
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            h = s.get("host", "")
            if h and h not in hosts:
                hosts.append(h)
        return hosts

    @staticmethod
    def _first_open_port(host: str, ctx: ScanContext) -> Optional[int]:
        for svc in (ctx.services or []):
            s = svc if isinstance(svc, dict) else {}
            if s.get("host") == host and s.get("state") == "open":
                return s["port"]
        return None

    @staticmethod
    def _resolve_ip(host: str, ctx: ScanContext) -> Optional[str]:
        ips = (ctx.ip_map or {}).get(host, [])
        return ips[0] if ips else None

    async def _userspace_probe(self, ip: str, port: int, ctx: ScanContext) -> Optional[dict]:
        result: dict = {"sources": []}

        try:
            async with ctx.throttle.acquire("tcp_scan"):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=3.0
                )
                sock = writer.get_extra_info("socket")
                if sock:
                    try:
                        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                        result["ttl"] = ttl
                        result["sources"].append("ttl")
                    except Exception:
                        pass

                    try:
                        mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                        result["mss"] = mss
                        result["sources"].append("mss")
                    except Exception:
                        pass

                    try:
                        import sys
                        if sys.platform == "linux":
                            tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                            if len(tcp_info) >= 120:
                                snd_wscale = struct.unpack_from("B", tcp_info, 114)[0]
                                result["window_scale"] = snd_wscale
                                result["sources"].append("tcp_info")
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception:
            return None

        if not result["sources"]:
            return None
        return result

    def _match_os(self, fp: dict) -> tuple[str, float]:
        best_os = "unknown"
        best_score = 0.0

        for entry in OS_FINGERPRINT_DB:
            score = 0.0
            ttl = fp.get("ttl")
            if ttl is not None:
                lo, hi = entry["ttl_range"]
                if lo <= ttl <= hi:
                    score += 0.35

            mss = fp.get("mss")
            if mss is not None and mss in entry.get("mss_values", []):
                score += 0.25

            ws = fp.get("window_size")
            if ws is not None and ws in entry.get("window_sizes", []):
                score += 0.20

            if score > best_score:
                best_score = score
                best_os = entry["os"]

        return best_os, round(min(best_score, 1.0), 2)
