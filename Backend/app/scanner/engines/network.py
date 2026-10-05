"""
QuantumShield — Network Scan Engine (Stage 2)

Pure-asyncio TCP port scanner and banner grabber. Replaces nmap subprocess
with stdlib ``asyncio.open_connection`` for connect-scanning. Includes strict
scope validation and evidence generation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import pathlib
import re
import socket
import uuid
from typing import Any

import dns.asyncresolver
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Timeout

from app.config import settings
from app.scanner.models import (
    ASNInfo,
    ServiceFingerprint,
    StageResult,
    NormalizedTarget,
    TargetAuthorization,
    NetworkObservation,
    PortState,
    PortResult,
)
from app.scanner.pipeline import (
    MergeStrategy,
    ScanContext,
    ScanStage,
    StageCriticality,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Scope & Target Normalization
# ---------------------------------------------------------------------------

class ScanScopePolicy:
    """Validates targets against security policies (e.g. blocking private IPs)."""
    @classmethod
    async def validate_target(cls, target: str) -> list[NormalizedTarget]:
        """
        Takes a raw string (IP or hostname).
        Resolves to IPs if it's a hostname.
        Filters out private/loopback/reserved IPs unless configured otherwise.
        Returns a list of NormalizedTarget.
        """
        targets = []
        is_ip = False
        parsed_ip = None
        
        try:
            parsed_ip = ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            auth = cls._is_authorized_ip(parsed_ip)
            targets.append(NormalizedTarget(
                hostname=None,
                ip=str(parsed_ip),
                ip_version=parsed_ip.version,
                authorization=auth
            ))
            return targets

        # It's a hostname, resolve it
        try:
            answers = await dns.asyncresolver.resolve(target, "A", lifetime=settings.SCANNER_DNS_TIMEOUT)
            for rdata in answers:
                ip_str = rdata.to_text()
                parsed_ip = ipaddress.ip_address(ip_str)
                auth = cls._is_authorized_ip(parsed_ip)
                targets.append(NormalizedTarget(
                    hostname=target,
                    ip=ip_str,
                    ip_version=parsed_ip.version,
                    authorization=auth
                ))
        except (NXDOMAIN, NoAnswer, NoNameservers, Timeout) as e:
            logger.debug(f"ScopePolicy: DNS resolution failed for {target} - {e}")
            
        if settings.NETWORK_ALLOW_IPV6:
            try:
                answers_v6 = await dns.asyncresolver.resolve(target, "AAAA", lifetime=settings.SCANNER_DNS_TIMEOUT)
                for rdata in answers_v6:
                    ip_str = rdata.to_text()
                    parsed_ip = ipaddress.ip_address(ip_str)
                    auth = cls._is_authorized_ip(parsed_ip)
                    targets.append(NormalizedTarget(
                        hostname=target,
                        ip=ip_str,
                        ip_version=parsed_ip.version,
                        authorization=auth
                    ))
            except Exception:
                pass
                
        return targets

    @staticmethod
    def _is_authorized_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> TargetAuthorization:
        if ip.is_loopback:
            return TargetAuthorization(allowed=False, reason="loopback_address")
        if ip.is_multicast:
            return TargetAuthorization(allowed=False, reason="multicast_address")
        if ip.is_link_local:
            return TargetAuthorization(allowed=False, reason="link_local_address")
        if ip.is_reserved:
            return TargetAuthorization(allowed=False, reason="reserved_address")
        if ip.is_unspecified:
            return TargetAuthorization(allowed=False, reason="unspecified_address")
        if ip.is_private and not settings.NETWORK_ALLOW_PRIVATE_TARGETS:
            return TargetAuthorization(allowed=False, reason="private_network_blocked")
            
        return TargetAuthorization(allowed=True, reason="authorized_asset")

class TargetNormalizer:
    @staticmethod
    def normalize(targets: list[NormalizedTarget]) -> dict[str, NormalizedTarget]:
        """Deduplicates targets by IP while preserving discovery relationships."""
        unique = {}
        for t in targets:
            if not t.authorization.allowed:
                logger.warning(f"TargetNormalizer: Rejected {t.ip} ({t.hostname}) - {t.authorization.reason}")
                continue
            if t.ip not in unique:
                unique[t.ip] = t
            else:
                # If we already have this IP, we might want to keep the hostname if we didn't have one
                if not unique[t.ip].hostname and t.hostname:
                    unique[t.ip].hostname = t.hostname
        return unique

# ---------------------------------------------------------------------------
# Port Scheduler
# ---------------------------------------------------------------------------

class PortScheduler:
    PORT_PROFILES = {
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

    @classmethod
    def select_ports(cls, profile_name: str) -> list[int]:
        return cls.PORT_PROFILES.get(profile_name, cls.PORT_PROFILES[settings.NETWORK_DEFAULT_PROFILE])
        
    @classmethod
    def get_critical_ports(cls) -> set[int]:
        return cls.CRITICAL_PORTS

# ---------------------------------------------------------------------------
# TCP Probe Layer & State Classifier
# ---------------------------------------------------------------------------

class PortStateClassifier:
    @staticmethod
    def classify(exception: Exception | None) -> PortState:
        if exception is None:
            return PortState.OPEN
        if isinstance(exception, (ConnectionRefusedError, ConnectionResetError)):
            return PortState.CLOSED
        if isinstance(exception, (asyncio.TimeoutError, TimeoutError)):
            return PortState.FILTERED
        if isinstance(exception, OSError):
            return PortState.ERROR
        return PortState.UNKNOWN

class TCPProbe:
    @staticmethod
    async def probe(ip: str, port: int, timeout: float) -> tuple[PortState, Exception | None]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return PortStateClassifier.classify(None), None
        except Exception as e:
            return PortStateClassifier.classify(e), e

# ---------------------------------------------------------------------------
# Adaptive Concurrency
# ---------------------------------------------------------------------------

class ConcurrencyController:
    def __init__(self, throttle):
        self.throttle = throttle

    async def scan_host_ports(self, ip: str, ports: list[int]) -> list[tuple[int, PortState]]:
        """Scans a host's ports with batching and adaptive throttling."""
        async def _throttled_scan(p: int) -> tuple[int, PortState]:
            async with self.throttle.acquire("tcp_scan"):
                # Retry logic for transient errors
                for attempt in range(settings.NETWORK_RETRY_COUNT + 1):
                    state, exc = await TCPProbe.probe(ip, p, settings.NETWORK_TCP_TIMEOUT)
                    # Retry on timeouts or socket errors, but not connection refused
                    if state in (PortState.FILTERED, PortState.ERROR) and attempt < settings.NETWORK_RETRY_COUNT:
                        await asyncio.sleep(settings.NETWORK_RETRY_BACKOFF)
                        continue
                    return p, state
                return p, state

        results = []
        remaining = list(ports)

        first_batch = remaining[:settings.NETWORK_BATCH_SIZE]
        remaining = remaining[settings.NETWORK_BATCH_SIZE:]

        batch_results = await asyncio.gather(*[_throttled_scan(p) for p in first_batch])
        
        closed_count = sum(1 for _, state in batch_results if state == PortState.CLOSED)
        results.extend(batch_results)

        if closed_count > settings.NETWORK_ADAPTIVE_THRESHOLD and remaining:
            remaining = [p for p in remaining if p in PortScheduler.get_critical_ports()]
            logger.info(
                f"Adaptive reduction for {ip}: {closed_count}/{len(first_batch)} closed in first batch — "
                f"narrowing remaining to {len(remaining)} critical ports"
            )

        while remaining:
            chunk = remaining[:settings.NETWORK_BATCH_SIZE]
            remaining = remaining[settings.NETWORK_BATCH_SIZE:]
            chunk_results = await asyncio.gather(*[_throttled_scan(p) for p in chunk])
            results.extend(chunk_results)

        return results

# ---------------------------------------------------------------------------
# Banner Processing & Service Detection
# ---------------------------------------------------------------------------

class BannerProcessor:
    BANNER_PROBES: dict[int, bytes | None] = {
        80:   b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
        443:  None,
        22:   b"",
        25:   b"",
        21:   b"",
        3306: b"",
        6379: b"PING\r\n",
    }
    DEFAULT_PROBE = b""

    @classmethod
    async def grab_banner(cls, ip: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=settings.NETWORK_BANNER_CONNECT_TIMEOUT,
            )
        except Exception:
            return None

        try:
            probe = cls.BANNER_PROBES.get(port, cls.DEFAULT_PROBE)
            if probe is None:
                writer.close()
                await writer.wait_closed()
                return None
                
            if probe and b"{host}" in probe:
                probe = probe.replace(b"{host}", ip.encode())
                
            if probe:
                writer.write(probe)
                await writer.drain()

            data = await asyncio.wait_for(
                reader.read(settings.NETWORK_MAX_BANNER_SIZE), 
                timeout=settings.NETWORK_BANNER_READ_TIMEOUT
            )
            return data[:settings.NETWORK_MAX_BANNER_SIZE].decode(errors="replace") if data else None
        except Exception:
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass


class ConfidenceAssessor:
    @staticmethod
    def assess(version: str | None, service_name: str, banner: str | None) -> str:
        """Returns string representation of confidence."""
        if version and banner:
            return "high"
        if banner and service_name != "unknown":
            return "medium"
        return "low"


class ServiceDetector:
    _SIGNATURES: list[dict[str, Any]] | None = None
    _SIGNATURES_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "service_signatures.json"

    _PROTOCOL_MAP: dict[str, str] = {
        "http": "web", "https": "web", "http_apache": "web", "http_nginx": "web",
        "smtp": "mail", "imap": "mail", "pop3": "mail",
        "mysql": "db", "postgresql": "db", "redis": "db", "mongodb": "db",
        "ssh_openssh": "remote", "rdp": "remote", "dns_bind": "dns"
    }
    
    _PORT_PROTOCOL_FALLBACK: dict[int, str] = {
        80: "web", 443: "web", 8080: "web", 8443: "web",
        25: "mail", 587: "mail", 143: "mail", 993: "mail",
        3306: "db", 5432: "db", 6379: "db", 27017: "db",
        22: "remote", 3389: "remote", 53: "dns",
    }

    @classmethod
    def _load_signatures(cls) -> list[dict[str, Any]]:
        if cls._SIGNATURES is not None:
            return cls._SIGNATURES
        try:
            cls._SIGNATURES = json.loads(cls._SIGNATURES_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load service_signatures.json: %s", exc)
            cls._SIGNATURES = []
        return cls._SIGNATURES

    @classmethod
    def classify_protocol(cls, service_name: str | None, port: int) -> str:
        if service_name and service_name in cls._PROTOCOL_MAP:
            return cls._PROTOCOL_MAP[service_name]
        return cls._PORT_PROTOCOL_FALLBACK.get(port, "unknown")

    @classmethod
    def detect(cls, host: str, port: int, banner: str | None) -> ServiceFingerprint:
        if not banner:
            return ServiceFingerprint(
                host=host, port=port, state="open", service_name="unknown",
                protocol_category=cls.classify_protocol("unknown", port), confidence="low"
            )

        signatures = cls._load_signatures()
        for entry in signatures:
            for pattern in entry.get("patterns", []):
                try:
                    if re.search(pattern, banner, re.IGNORECASE):
                        version = None
                        ver_re = entry.get("version_regex")
                        if ver_re:
                            m = re.search(ver_re, banner, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                                
                        svc_name = entry["service"]
                        return ServiceFingerprint(
                            host=host, port=port, state="open",
                            service_name=svc_name,
                            product=svc_name.split("_", 1)[-1] if "_" in svc_name else svc_name,
                            version=version,
                            raw_banner=banner[:512],
                            protocol_category=cls.classify_protocol(svc_name, port),
                            confidence=ConfidenceAssessor.assess(version, svc_name, banner)
                        )
                except re.error:
                    continue

        return ServiceFingerprint(
            host=host, port=port, state="open", service_name="unknown",
            raw_banner=banner[:512],
            protocol_category=cls.classify_protocol("unknown", port),
            confidence="low"
        )


# ---------------------------------------------------------------------------
# Evidence Generator
# ---------------------------------------------------------------------------

class EvidenceGenerator:
    @staticmethod
    def generate_port_evidence(target: NormalizedTarget, port: int, state: PortState) -> NetworkObservation:
        return NetworkObservation(
            evidence_id=f"ev-{uuid.uuid4().hex[:12]}",
            observation_type=f"tcp_port_{state.value}",
            target=target.ip,
            port=port,
            confidence=1.0 if state in (PortState.OPEN, PortState.CLOSED) else 0.8
        )

    @staticmethod
    def generate_service_evidence(target: NormalizedTarget, port: int, service: ServiceFingerprint) -> NetworkObservation:
        conf_map = {"high": 0.95, "medium": 0.7, "low": 0.4}
        return NetworkObservation(
            evidence_id=f"ev-{uuid.uuid4().hex[:12]}",
            observation_type="service_detected",
            target=target.ip,
            port=port,
            confidence=conf_map.get(service.confidence, 0.5)
        )

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class NetworkScanEngine(ScanStage):
    name = "network"
    order = 2
    timeout_seconds = 120
    criticality = StageCriticality.CRITICAL
    required_fields = ["subdomains"]
    writes_fields = ["services", "assets", "evidence"]
    merge_strategy = MergeStrategy.OVERWRITE

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
                            asn=parts[0] or None, prefix=parts[1] or None,
                            country=parts[2] or None, registry=parts[3] or None,
                            org=parts[4] or None
                        )
        except Exception:
            pass
        return ASNInfo()

    async def execute(self, ctx: ScanContext) -> StageResult:
        request_count = 0
        
        profile_name = ctx.options.get("port_profile", settings.NETWORK_DEFAULT_PROFILE)
        ports = PortScheduler.select_ports(profile_name)

        # Build initial target list from context
        raw_targets = []
        for subdomain, ips in (ctx.ip_map or {}).items():
            ip_list = ips if isinstance(ips, list) else [ips]
            for ip in ip_list:
                raw_targets.append(ip)
                
        if not raw_targets and ctx.subdomains:
            for sub in ctx.subdomains:
                if isinstance(sub, str):
                    raw_targets.append(sub)
                elif isinstance(sub, dict):
                    host = sub.get("hostname") or sub.get("subdomain")
                    if host:
                        raw_targets.append(host)

        # 1. Scope & Target Normalization
        normalized_targets = []
        for t in raw_targets:
            normalized_targets.extend(await ScanScopePolicy.validate_target(t))
            request_count += 1
            
        unique_targets = TargetNormalizer.normalize(normalized_targets)
        
        if not unique_targets:
            return StageResult(status="success", data={"services": [], "assets": [], "evidence": []})

        all_services: list[dict] = []
        assets: list[dict] = []
        all_evidence: list[NetworkObservation] = []
        asn_cache: dict[str, ASNInfo] = {}

        # 2. ASN Lookups
        if settings.SCANNER_ENABLE_ASN_LOOKUP:
            asn_tasks = {ip: self._lookup_asn(ip, ctx) for ip in unique_targets}
            asn_results = await asyncio.gather(*asn_tasks.values(), return_exceptions=True)
            for ip, result in zip(asn_tasks.keys(), asn_results):
                request_count += 1
                asn_cache[ip] = ASNInfo() if isinstance(result, BaseException) else result
        else:
            for ip in unique_targets:
                asn_cache[ip] = ASNInfo()

        # 3. Scanning with ConcurrencyController
        controller = ConcurrencyController(ctx.throttle)
        
        for ip, target_obj in unique_targets.items():
            port_states = await controller.scan_host_ports(ip, ports)
            request_count += len(ports)
            
            open_ports = []
            ip_services = []
            
            for port, state in port_states:
                # Evidence: Port state
                ev = EvidenceGenerator.generate_port_evidence(target_obj, port, state)
                all_evidence.append(ev)
                
                if state == PortState.OPEN:
                    open_ports.append(PortResult(
                        ip=ip, port=port, state=state, evidence_ids=[ev.evidence_id]
                    ))
                    
                    banner = await BannerProcessor.grab_banner(ip, port)
                    request_count += 1
                    
                    fp = ServiceDetector.detect(
                        host=target_obj.hostname or ip,
                        port=port,
                        banner=banner
                    )
                    ip_services.append(fp)
                    
                    # Evidence: Service detection
                    svc_ev = EvidenceGenerator.generate_service_evidence(target_obj, port, fp)
                    all_evidence.append(svc_ev)
                    # Link evidence to PortResult
                    open_ports[-1].service = fp
                    open_ports[-1].evidence_ids.append(svc_ev.evidence_id)
            
            all_services.extend(s.model_dump() for s in ip_services)
            
            # Asset correlation
            assets.append({
                "hostname": target_obj.hostname or ip,
                "ip": ip,
                "asn": asn_cache.get(ip, ASNInfo()).model_dump(),
                "open_ports": [p.model_dump() for p in open_ports],
                "services": [s.model_dump() for s in ip_services],
            })

        logger.info(
            "NetworkScanEngine complete — %d IPs, %d open ports, %d services, %d pieces of evidence, %d requests",
            len(unique_targets),
            sum(len(a["open_ports"]) for a in assets),
            len(all_services),
            len(all_evidence),
            request_count,
        )

        return StageResult(
            status="success",
            data={
                "services": all_services,
                "assets": assets,
                "evidence": [e.model_dump() for e in all_evidence]
            },
            request_count=request_count,
        )
