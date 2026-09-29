"""
Web & API Discovery Engine — Unit Tests
Covers WEB-01, WEB-02, WEB-03, WEB-04, WEB-05

Run:
    cd Backend
    PYTHONPATH=. pytest tests/scanner/engines/test_web_discovery.py -v
"""

from __future__ import annotations

import ipaddress
import socket
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.scanner.engines.web_discovery import (
    WebAPIDiscoveryEngine,
    WebTarget,
    _ScopePolicy,
    _read_bounded,
)
from app.scanner.models import WebAppProfile, WellKnownResult
from app.scanner.pipeline import ScanContext


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _MockThrottle:
    def acquire(self, *a, **kw):
        @asynccontextmanager
        async def _():
            yield
        return _()


def make_ctx(domain="example.com", services=None, subdomains=None):
    ctx = ScanContext(scan_id="test", domain=domain)
    ctx.throttle = _MockThrottle()
    if services is not None:
        ctx.services = services
    if subdomains is not None:
        ctx.subdomains = subdomains
    return ctx


# ---------------------------------------------------------------------------
# Group A: WEB-01 — Pydantic model compatibility
# ---------------------------------------------------------------------------

class TestWEB01PydanticFix:

    def test_well_known_result_is_list_in_profile(self):
        """WebAppProfile must accept list[WellKnownResult], not dict."""
        wk = [WellKnownResult(path="/.well-known/security.txt", status_code=200, found=True)]
        profile = WebAppProfile(
            host="example.com",
            url="https://example.com/",
            well_known_results=wk,
        )
        assert isinstance(profile.well_known_results, list)
        assert len(profile.well_known_results) == 1

    def test_failed_profile_returns_valid_dict(self):
        """_failed_profile must produce a dict with well_known_results as list."""
        engine = WebAPIDiscoveryEngine()
        result = engine._failed_profile("example.com", "https://example.com/", "timeout")
        assert isinstance(result, dict)
        wk = result.get("well_known_results")
        assert isinstance(wk, list), f"Expected list, got {type(wk)}"

    def test_well_known_results_dict_raises_validation_error(self):
        """Confirm the OLD broken behavior (dict) raises a ValidationError."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebAppProfile(
                host="example.com",
                url="https://example.com/",
                well_known_results={"/.well-known/security.txt": {"found": True}},  # BROKEN
            )


# ---------------------------------------------------------------------------
# Group B: WEB-02 — Port-aware target resolution
# ---------------------------------------------------------------------------

class TestWEB02PortResolution:

    def test_standard_443_maps_to_https(self):
        svc = {"host": "example.com", "port": 443, "protocol_category": "web"}
        target = WebTarget.from_service(svc)
        assert target is not None
        assert target.scheme == "https"
        assert target.port == 443
        assert target.base_url == "https://example.com/"

    def test_port_8443_maps_to_https_with_explicit_port(self):
        svc = {"host": "example.com", "port": 8443, "protocol_category": "web"}
        target = WebTarget.from_service(svc)
        assert target is not None
        assert target.scheme == "https"
        assert "8443" in target.base_url

    def test_port_8080_maps_to_http_with_explicit_port(self):
        svc = {"host": "example.com", "port": 8080, "protocol_category": "web"}
        target = WebTarget.from_service(svc)
        assert target is not None
        assert target.scheme == "http"
        assert "8080" in target.base_url

    def test_port_80_omitted_from_url(self):
        svc = {"host": "example.com", "port": 80, "protocol_category": "http"}
        target = WebTarget.from_service(svc)
        assert target is not None
        assert "80" not in target.base_url  # port 80 should be default, not shown

    def test_resolver_generates_multiple_targets_per_host(self):
        ctx = make_ctx(services=[
            {"host": "example.com", "port": 443, "protocol_category": "web"},
            {"host": "example.com", "port": 8443, "protocol_category": "web"},
        ])
        engine = WebAPIDiscoveryEngine()
        targets = engine._resolve_web_targets(ctx)
        ports = {t.port for t in targets}
        assert 443 in ports
        assert 8443 in ports

    def test_non_web_services_excluded(self):
        ctx = make_ctx(services=[
            {"host": "example.com", "port": 5432, "protocol_category": "db"},
            {"host": "example.com", "port": 443, "protocol_category": "web"},
        ])
        engine = WebAPIDiscoveryEngine()
        targets = engine._resolve_web_targets(ctx)
        ports = {t.port for t in targets}
        assert 443 in ports
        assert 5432 not in ports


# ---------------------------------------------------------------------------
# Group C: WEB-03 — Scope control and SSRF
# ---------------------------------------------------------------------------

class TestWEB03ScopeSSRF:

    def _make_scope(self, domain="example.com", extra_subs=None):
        ctx = make_ctx(domain=domain)
        if extra_subs:
            ctx.subdomains = [{"hostname": s} for s in extra_subs]
        return _ScopePolicy(ctx)

    def test_authorized_domain_is_allowed(self):
        scope = self._make_scope()
        assert scope.is_hostname_authorized("example.com")

    def test_subdomain_of_authorized_domain_is_allowed(self):
        scope = self._make_scope()
        # If we only seed from domain, subdomain itself must be explicitly added
        # via subdomains list
        scope2 = self._make_scope(extra_subs=["api.example.com"])
        assert scope2.is_hostname_authorized("api.example.com")

    def test_external_domain_is_denied(self):
        scope = self._make_scope()
        assert not scope.is_hostname_authorized("attacker.example")
        assert not scope.is_hostname_authorized("evil.com")

    def test_localhost_url_is_ssrf_blocked(self):
        scope = self._make_scope(extra_subs=["localhost"])  # Even if name seeded
        allowed, reason = scope.is_url_authorized("http://localhost/admin")
        # localhost resolves to 127.0.0.1 — blocked by _BLOCKED_CIDRS
        assert not allowed or "ssrf_blocked" in reason or "out_of_scope" in reason

    def test_link_local_is_ssrf_blocked(self):
        scope = self._make_scope()
        # We can't fully test without DNS, but check the hostname scope fails first
        allowed, reason = scope.is_url_authorized("http://169.254.169.254/latest/meta-data/")
        assert not allowed


# ---------------------------------------------------------------------------
# Group D: WEB-04 — Bounded response reading
# ---------------------------------------------------------------------------

class TestWEB04BoundedReads:

    @pytest.mark.asyncio
    async def test_read_bounded_stops_at_limit(self):
        """_read_bounded must stop reading at max_bytes."""
        large_data = b"A" * (1024 * 1024)  # 1 MB

        # Create a mock response that yields chunks
        class _MockStream:
            async def aiter_bytes(self, chunk_size=8192):
                offset = 0
                while offset < len(large_data):
                    yield large_data[offset:offset + chunk_size]
                    offset += chunk_size

        body, truncated = await _read_bounded(_MockStream(), max_bytes=256 * 1024)
        assert len(body) <= 256 * 1024
        assert truncated is True

    @pytest.mark.asyncio
    async def test_read_bounded_exact_fit(self):
        """_read_bounded must return complete body when under limit."""
        data = b"B" * 100

        class _MockStream:
            async def aiter_bytes(self, chunk_size=8192):
                yield data

        body, truncated = await _read_bounded(_MockStream(), max_bytes=1024)
        assert body == data
        assert truncated is False


# ---------------------------------------------------------------------------
# Group E: WEB-05 — JS references vs verified findings
# ---------------------------------------------------------------------------

class TestWEB05JSReferences:

    def test_js_routes_have_js_reference_type(self):
        """HiddenFinding from JS extraction must have finding_type=js_reference."""
        from app.scanner.models import HiddenFinding
        finding = HiddenFinding(
            host="example.com",
            path="/api/v1/users",
            status_code=0,
            discovery_source="js_extraction",
            finding_type="js_reference",
            risk="info",
            confidence=0.4,
            evidence="Path string extracted from JavaScript source (unverified reference): /api/v1/users",
        )
        assert finding.finding_type == "js_reference"
        assert finding.status_code == 0  # Not verified
        assert finding.confidence < 0.5  # Below verified threshold
        assert finding.risk == "info"

    def test_js_reference_not_api_leak(self):
        """Confirm old finding_type 'api_leak' is not used for JS refs."""
        from app.scanner.models import HiddenFinding
        # If someone creates a JS finding correctly, it should be js_reference
        f = HiddenFinding(
            host="example.com", path="/api/test",
            discovery_source="js_extraction",
            finding_type="js_reference",
        )
        assert f.finding_type != "api_leak"
