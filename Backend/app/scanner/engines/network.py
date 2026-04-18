"""
QuantumShield — Network Scan Engine (Stage 2)

Pure-asyncio TCP port scanner and banner grabber.  Replaces nmap subprocess
with stdlib ``asyncio.open_connection`` for connect-scanning and
``dnspython`` for ASN lookups via Cymru.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
from typing import Any

import dns.asyncresolver

from app.config import settings
from app.scanner.models import ASNInfo, PortResult, ServiceFingerprint, StageResult
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Port profiles
# ---------------------------------------------------------------------------

PORT_PROFILES: dict[str, list[int]] = {
    "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443],
    "banking": [
        21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
        993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9090,
        15672, 27017,
    ],
    "standard": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
        8888, 27017,
    ],
}

CRITICAL_PORTS = {21, 22, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443}

# ---------------------------------------------------------------------------
# Banner probes — keyed by port number
# ---------------------------------------------------------------------------

BANNER_PROBES: dict[int, bytes | None] = {
    80:   b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443:  None,
    22:   b"",
    25:   b"",
    21:   b"",
    3306: b"",
    6379: b"PING\r\n",
}
_DEFAULT_PROBE = b""

# ---------------------------------------------------------------------------
# Signature cache (module-level, loaded once)
# ---------------------------------------------------------------------------

_SIGNATURES: list[dict[str, Any]] | None = None
_SIGNATURES_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "service_signatures.json"


def _load_signatures() -> list[dict[str, Any]]:
    global _SIGNATURES
    if _SIGNATURES is not None:
        return _SIGNATURES
    try:
        _SIGNATURES = json.loads(_SIGNATURES_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("service_signatures.json not found at %s", _SIGNATURES_PATH)
        _SIGNATURES = []
    except json.JSONDecodeError as exc:
        logger.error("Malformed service_signatures.json: %s", exc)
        _SIGNATURES = []
    return _SIGNATURES


# ---------------------------------------------------------------------------
# Protocol classification helpers
# ---------------------------------------------------------------------------

_PROTOCOL_MAP: dict[str, str] = {}
for _svc in ("http", "https", "http_apache", "http_nginx", "http_iis",
             "http_litespeed", "http_caddy", "http_tomcat", "http_nodejs",
             "http_python_werkzeug", "http_python_gunicorn",
             "http_python_uvicorn"):
    _PROTOCOL_MAP[_svc] = "web"
for _svc in ("smtp", "smtp_postfix", "smtp_exim", "smtp_exchange",
             "smtp_sendmail", "imap", "imap_dovecot", "imap_cyrus", "pop3"):
    _PROTOCOL_MAP[_svc] = "mail"
for _svc in ("mysql", "mariadb", "postgresql", "mssql", "redis",
             "mongodb", "elasticsearch", "memcached"):
    _PROTOCOL_MAP[_svc] = "db"
for _svc in ("ssh_openssh", "ssh_dropbear", "rdp", "vnc"):
    _PROTOCOL_MAP[_svc] = "remote"
for _svc in ("dns_bind",):
    _PROTOCOL_MAP[_svc] = "dns"

_PORT_PROTOCOL_FALLBACK: dict[int, str] = {
    80: "web", 443: "web", 8080: "web", 8443: "web", 8000: "web",
    8888: "web", 3000: "web", 5000: "web", 9000: "web", 9443: "web",
    25: "mail", 465: "mail", 587: "mail", 110: "mail", 143: "mail",
    993: "mail", 995: "mail",
    3306: "db", 5432: "db", 1433: "db", 6379: "db", 27017: "db",
    22: "remote", 3389: "remote", 5900: "remote",
    53: "dns",
}

_BATCH_SIZE = 50
_ADAPTIVE_CLOSED_THRESHOLD = 40


# ═══════════════════════════════════════════════════════════════════════
# NetworkScanEngine
# ═══════════════════════════════════════════════════════════════════════

class NetworkScanEngine(ScanStage):
    name = "network"
    order = 2
    timeout_seconds = 120
    criticality = StageCriticality.CRITICAL
    required_fields = ["subdomains"]  # runs even without ip_map — will attempt hostname-based scanning
    writes_fields = ["services", "assets"]
    merge_strategy = MergeStrategy.OVERWRITE

    # ── single port probe ─────────────────────────────────────────────

    @staticmethod
    async def _scan_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return PortResult(ip=ip, port=port, state="open")
        except (ConnectionRefusedError, ConnectionResetError):
            return PortResult(ip=ip, port=port, state="closed")
        except (asyncio.TimeoutError, TimeoutError):
            return PortResult(ip=ip, port=port, state="filtered")
        except OSError:
            return PortResult(ip=ip, port=port, state="error")

    # ── host-level scan with adaptive batch strategy ──────────────────

    async def _scan_host(
        self,
        ip: str,
        ports: list[int],
        ctx: ScanContext,
    ) -> list[PortResult]:

        async def _throttled_scan(p: int) -> PortResult:
            async with ctx.throttle.acquire("tcp_scan"):
                return await self._scan_port(ip, p)

        results: list[PortResult] = []
        remaining = list(ports)

        first_batch = remaining[:_BATCH_SIZE]
        remaining = remaining[_BATCH_SIZE:]

        batch_results = await asyncio.gather(
            *[_throttled_scan(p) for p in first_batch],
            return_exceptions=True,
        )
        closed_count = 0
        for r in batch_results:
            if isinstance(r, BaseException):
                continue
            results.append(r)
            if r.state == "closed":
                closed_count += 1

        if closed_count > _ADAPTIVE_CLOSED_THRESHOLD and remaining:
            remaining = [p for p in remaining if p in CRITICAL_PORTS]
            logger.info(
                "Adaptive reduction for %s: %d/%d closed in first batch — "
                "narrowing remaining to %d critical ports",
                ip, closed_count, len(first_batch), len(remaining),
            )

        while remaining:
            chunk = remaining[:_BATCH_SIZE]
            remaining = remaining[_BATCH_SIZE:]
            chunk_results = await asyncio.gather(
                *[_throttled_scan(p) for p in chunk],
                return_exceptions=True,
            )
            for r in chunk_results:
                if not isinstance(r, BaseException):
                    results.append(r)

        return [r for r in results if r.state == "open"]

    # ── banner grabbing ───────────────────────────────────────────────

    @staticmethod
    async def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except (OSError, asyncio.TimeoutError, TimeoutError):
            return None

        try:
            probe = BANNER_PROBES.get(port, _DEFAULT_PROBE)
            if probe is None:
                writer.close()
                await writer.wait_closed()
                return None
            if probe and b"{host}" in probe:
                probe = probe.replace(b"{host}", ip.encode())
            if probe:
                writer.write(probe)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            return data[:4096].decode(errors="replace") if data else None
        except (OSError, asyncio.TimeoutError, TimeoutError):
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    # ── service fingerprinting ────────────────────────────────────────

    def _fingerprint_service(
        self,
        host: str,
        port: int,
        banner: str | None,
    ) -> ServiceFingerprint:
        if not banner:
            return ServiceFingerprint(
                host=host,
                port=port,
                state="open",
                service_name="unknown",
                protocol_category=self._classify_protocol("unknown", port),
            )

        signatures = _load_signatures()
        for entry in signatures:
            for pattern in entry.get("patterns", []):
                try:
                    if re.search(pattern, banner, re.IGNORECASE):
                        version: str | None = None
                        ver_re = entry.get("version_regex")
                        if ver_re:
                            m = re.search(ver_re, banner, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                        svc_name = entry["service"]
                        return ServiceFingerprint(
                            host=host,
                            port=port,
                            state="open",
                            service_name=svc_name,
                            product=svc_name.split("_", 1)[-1] if "_" in svc_name else svc_name,
                            version=version,
                            raw_banner=banner[:512],
                            protocol_category=self._classify_protocol(svc_name, port),
                            confidence="high" if version else "medium",
                        )
                except re.error:
                    continue

        return ServiceFingerprint(
            host=host,
            port=port,
            state="open",
            service_name="unknown",
            raw_banner=banner[:512],
            protocol_category=self._classify_protocol("unknown", port),
        )

    # ── ASN lookup via Cymru ──────────────────────────────────────────

    @staticmethod
    async def _lookup_asn(ip: str, ctx: ScanContext) -> ASNInfo:
        try:
            async with ctx.throttle.acquire("dns"):
                reversed_ip = ".".join(reversed(ip.split(".")))
                qname = f"{reversed_ip}.origin.asn.cymru.com"
                answers = await dns.asyncresolver.resolve(qname, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 5:
                        return ASNInfo(
                            asn=parts[0] or None,
                            prefix=parts[1] or None,
                            country=parts[2] or None,
                            registry=parts[3] or None,
                            org=parts[4] or None,
                        )
        except Exception as exc:
            logger.debug("ASN lookup failed for %s: %s", ip, exc)
        return ASNInfo()

    # ── protocol classification ───────────────────────────────────────

    @staticmethod
    def _classify_protocol(service_name: str | None, port: int) -> str:
        if service_name and service_name in _PROTOCOL_MAP:
            return _PROTOCOL_MAP[service_name]
        return _PORT_PROTOCOL_FALLBACK.get(port, "unknown")

    # ══════════════════════════════════════════════════════════════════
    # execute — main entry point
    # ══════════════════════════════════════════════════════════════════

    async def execute(self, ctx: ScanContext) -> StageResult:
        request_count = 0

        profile_name = ctx.options.get("port_profile", "standard")
        ports = PORT_PROFILES.get(profile_name, PORT_PROFILES["standard"])

        unique_ips: dict[str, list[str]] = {}
        for subdomain, ips in (ctx.ip_map or {}).items():
            ip_list = ips if isinstance(ips, list) else [ips]
            for ip in ip_list:
                unique_ips.setdefault(ip, []).append(subdomain)

        # Fallback: when ip_map is empty, scan subdomains by hostname directly
        # (asyncio.open_connection accepts hostnames — the OS resolves them)
        if not unique_ips and ctx.subdomains:
            for sub in ctx.subdomains:
                if isinstance(sub, str):
                    host = sub.strip().lower()
                elif isinstance(sub, dict):
                    host = (sub.get("hostname") or sub.get("subdomain") or "").strip().lower()
                else:
                    host = str(sub).strip().lower()
                if host:
                    unique_ips.setdefault(host, []).append(host)

        if not unique_ips:
            return StageResult(status="success", data={"services": [], "assets": []})

        all_services: list[dict] = []
        assets: list[dict] = []
        asn_cache: dict[str, ASNInfo] = {}

        # --- Optional ASN lookups (external intelligence) ---
        if settings.SCANNER_ENABLE_ASN_LOOKUP:
            asn_tasks = {
                ip: self._lookup_asn(ip, ctx) for ip in unique_ips
            }
            asn_results = await asyncio.gather(
                *asn_tasks.values(), return_exceptions=True,
            )
            for ip, result in zip(asn_tasks.keys(), asn_results):
                request_count += 1
                if isinstance(result, BaseException):
                    asn_cache[ip] = ASNInfo()
                else:
                    asn_cache[ip] = result
        else:
            for ip in unique_ips:
                asn_cache[ip] = ASNInfo()

        # --- Port scanning + banner + fingerprint per IP ---
        for ip, subdomains in unique_ips.items():
            open_ports = await self._scan_host(ip, ports, ctx)
            request_count += len(ports)

            ip_services: list[ServiceFingerprint] = []
            for pr in open_ports:
                banner = await self._grab_banner(ip, pr.port)
                request_count += 1
                fp = self._fingerprint_service(
                    host=subdomains[0] if subdomains else ip,
                    port=pr.port,
                    banner=banner,
                )
                ip_services.append(fp)

            all_services.extend(s.model_dump() for s in ip_services)

            for sub in subdomains:
                assets.append({
                    "hostname": sub,
                    "ip": ip,
                    "asn": asn_cache.get(ip, ASNInfo()).model_dump(),
                    "open_ports": [
                        {"port": p.port, "state": p.state} for p in open_ports
                    ],
                    "services": [s.model_dump() for s in ip_services],
                })

        logger.info(
            "NetworkScanEngine complete — %d IPs, %d open ports, %d services, %d requests",
            len(unique_ips),
            sum(len(a["open_ports"]) for a in assets),
            len(all_services),
            request_count,
        )

        return StageResult(
            status="success",
            data={"services": all_services, "assets": assets},
            request_count=request_count,
        )
