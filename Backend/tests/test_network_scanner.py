import pytest
import asyncio
import ipaddress
from unittest.mock import AsyncMock, patch

from app.scanner.engines.network import (
    ScanScopePolicy,
    TargetNormalizer,
    PortScheduler,
    TCPProbe,
    PortStateClassifier,
    ServiceDetector,
    ConfidenceAssessor,
    EvidenceGenerator,
)
from app.scanner.models import PortState, NormalizedTarget, TargetAuthorization

@pytest.mark.asyncio
async def test_scan_scope_policy_ipv4_public():
    # Public IP
    targets = await ScanScopePolicy.validate_target("8.8.8.8")
    assert len(targets) == 1
    assert targets[0].ip == "8.8.8.8"
    assert targets[0].authorization.allowed is True

@pytest.mark.asyncio
async def test_scan_scope_policy_ipv4_private(monkeypatch):
    # Private IP should be blocked by default
    monkeypatch.setattr("app.config.settings.NETWORK_ALLOW_PRIVATE_TARGETS", False)
    targets = await ScanScopePolicy.validate_target("192.168.1.1")
    assert len(targets) == 1
    assert targets[0].ip == "192.168.1.1"
    assert targets[0].authorization.allowed is False
    assert targets[0].authorization.reason == "private_network_blocked"

    # With allow flag
    monkeypatch.setattr("app.config.settings.NETWORK_ALLOW_PRIVATE_TARGETS", True)
    targets2 = await ScanScopePolicy.validate_target("192.168.1.1")
    assert targets2[0].authorization.allowed is True

@pytest.mark.asyncio
async def test_scan_scope_policy_loopback():
    targets = await ScanScopePolicy.validate_target("127.0.0.1")
    assert len(targets) == 1
    assert targets[0].authorization.allowed is False
    assert targets[0].authorization.reason == "loopback_address"

@pytest.mark.asyncio
async def test_scan_scope_policy_hostname(monkeypatch):
    # Mock DNS resolution
    class MockAnswer:
        def __init__(self, ip):
            self.ip = ip
        def to_text(self):
            return self.ip

    async def mock_resolve(name, qtype, lifetime):
        if qtype == "A":
            return [MockAnswer("93.184.216.34"), MockAnswer("127.0.0.1")]
        raise Exception("No IPv6")

    monkeypatch.setattr("dns.asyncresolver.resolve", mock_resolve)
    
    targets = await ScanScopePolicy.validate_target("example.com")
    assert len(targets) == 2
    
    # One is public and allowed
    t_public = next(t for t in targets if t.ip == "93.184.216.34")
    assert t_public.hostname == "example.com"
    assert t_public.authorization.allowed is True
    
    # One is loopback and blocked (simulating DNS rebinding to localhost)
    t_local = next(t for t in targets if t.ip == "127.0.0.1")
    assert t_local.authorization.allowed is False

def test_target_normalizer():
    targets = [
        NormalizedTarget(hostname="test.com", ip="1.1.1.1", authorization=TargetAuthorization(allowed=True, reason="ok")),
        NormalizedTarget(hostname="test.com", ip="1.1.1.1", authorization=TargetAuthorization(allowed=True, reason="ok")),
        NormalizedTarget(hostname=None, ip="1.1.1.1", authorization=TargetAuthorization(allowed=True, reason="ok")),
        NormalizedTarget(hostname="bad.com", ip="127.0.0.1", authorization=TargetAuthorization(allowed=False, reason="loopback")),
    ]
    unique = TargetNormalizer.normalize(targets)
    assert len(unique) == 1
    assert "1.1.1.1" in unique
    assert unique["1.1.1.1"].hostname == "test.com"
    assert "127.0.0.1" not in unique

def test_port_scheduler():
    ports = PortScheduler.select_ports("web")
    assert 80 in ports
    assert 443 in ports
    
    critical = PortScheduler.get_critical_ports()
    assert 443 in critical
    assert 22 in critical

@pytest.mark.asyncio
async def test_tcp_probe_open(monkeypatch):
    mock_writer = AsyncMock()
    
    async def mock_open_connection(ip, port):
        return (AsyncMock(), mock_writer)
        
    monkeypatch.setattr("asyncio.open_connection", mock_open_connection)
    
    state, exc = await TCPProbe.probe("1.2.3.4", 80, 1.0)
    assert state == PortState.OPEN
    assert exc is None
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_awaited_once()

@pytest.mark.asyncio
async def test_tcp_probe_closed(monkeypatch):
    async def mock_open_connection(ip, port):
        raise ConnectionRefusedError()
        
    monkeypatch.setattr("asyncio.open_connection", mock_open_connection)
    
    state, exc = await TCPProbe.probe("1.2.3.4", 80, 1.0)
    assert state == PortState.CLOSED
    assert isinstance(exc, ConnectionRefusedError)

@pytest.mark.asyncio
async def test_tcp_probe_filtered(monkeypatch):
    async def mock_open_connection(ip, port):
        raise asyncio.TimeoutError()
        
    monkeypatch.setattr("asyncio.open_connection", mock_open_connection)
    
    state, exc = await TCPProbe.probe("1.2.3.4", 80, 1.0)
    assert state == PortState.FILTERED
    assert isinstance(exc, asyncio.TimeoutError)

def test_service_detector():
    # SSH banner
    banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    fp = ServiceDetector.detect("1.1.1.1", 22, banner)
    assert fp.service_name == "ssh_openssh"
    assert fp.confidence == "high"
    assert fp.version == "8.2p1"
    
    # Unknown banner
    banner2 = "HELLO_WORLD\n"
    fp2 = ServiceDetector.detect("1.1.1.1", 8080, banner2)
    assert fp2.service_name == "unknown"
    assert fp2.confidence == "low"
    assert fp2.protocol_category == "web"  # Fallback for 8080
    
    # Empty banner
    fp3 = ServiceDetector.detect("1.1.1.1", 443, None)
    assert fp3.service_name == "unknown"
    assert fp3.confidence == "low"

def test_evidence_generator():
    target = NormalizedTarget(hostname="api.com", ip="10.0.0.1", authorization=TargetAuthorization(allowed=True, reason="ok"))
    
    ev_port = EvidenceGenerator.generate_port_evidence(target, 443, PortState.OPEN)
    assert ev_port.observation_type == "tcp_port_open"
    assert ev_port.target == "10.0.0.1"
    assert ev_port.confidence == 1.0
    
    fp = ServiceDetector.detect("1.1.1.1", 443, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
    ev_svc = EvidenceGenerator.generate_service_evidence(target, 443, fp)
    assert ev_svc.observation_type == "service_detected"
    assert ev_svc.target == "10.0.0.1"
    assert ev_svc.confidence == 0.95  # high confidence
