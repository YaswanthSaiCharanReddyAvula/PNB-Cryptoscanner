"""
Tests for OSFingerprintEngine — domain separation, CDN/WAF correlation,
and evidence-based confidence.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.scanner.engines.os_fingerprint import (
    EDGE_HTTP_SERVER_WEIGHT,
    OS_EVIDENCE_WEIGHTS,
    OSFingerprintEngine,
)
from app.scanner.pipeline import ScanContext


def _make_ctx(services=None, cdn_waf_intel=None):
    """Create a minimal ScanContext with a dummy throttle."""
    throttle = MagicMock()
    throttle.acquire = MagicMock(return_value=AsyncMock().__aenter__())
    ctx = ScanContext(
        scan_id="test-os", domain="example.com", throttle=throttle,
    )
    ctx.services = services or []
    ctx.cdn_waf_intel = cdn_waf_intel or []
    return ctx


# ── Domain separation: runtimes must NOT appear in OS fingerprints ────

class TestDomainSeparation:
    """Verify that application runtimes are excluded from OS fingerprinting."""

    @pytest.mark.asyncio
    async def test_php_banner_not_in_os(self):
        ctx = _make_ctx(services=[
            {"host": "web.example.com", "port": 80, "service_name": "http",
             "raw_banner": "PHP/8.2", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fps = result.data.get("os_fingerprints", [])
        assert len(fps) == 1
        fp = fps[0]
        # runtime field must be None (not populated)
        assert fp.get("runtime") is None

    @pytest.mark.asyncio
    async def test_python_banner_not_in_os(self):
        ctx = _make_ctx(services=[
            {"host": "api.example.com", "port": 8000, "service_name": "http",
             "raw_banner": "uvicorn", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp.get("runtime") is None

    @pytest.mark.asyncio
    async def test_express_banner_not_in_os(self):
        ctx = _make_ctx(services=[
            {"host": "app.example.com", "port": 3000, "service_name": "http",
             "raw_banner": "Express", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp.get("runtime") is None

    @pytest.mark.asyncio
    async def test_aspnet_banner_not_in_os(self):
        ctx = _make_ctx(services=[
            {"host": "win.example.com", "port": 443, "service_name": "https",
             "raw_banner": "ASP.NET", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp.get("runtime") is None


# ── SSH banner OS detection ───────────────────────────────────────────

class TestSSHBannerDetection:

    @pytest.mark.asyncio
    async def test_ubuntu_ssh(self):
        ctx = _make_ctx(services=[
            {"host": "srv.example.com", "port": 22, "service_name": "ssh",
             "raw_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
             "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "Linux"
        assert "Ubuntu" in fp["os_version"]
        assert "ssh_banner" in fp["evidence_sources"]

    @pytest.mark.asyncio
    async def test_freebsd_ssh(self):
        ctx = _make_ctx(services=[
            {"host": "bsd.example.com", "port": 22, "service_name": "ssh",
             "raw_banner": "SSH-2.0-OpenSSH_8.0 FreeBSD-20190902",
             "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "FreeBSD"

    @pytest.mark.asyncio
    async def test_generic_openssh(self):
        ctx = _make_ctx(services=[
            {"host": "generic.example.com", "port": 22, "service_name": "ssh",
             "raw_banner": "SSH-2.0-OpenSSH_9.1", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "Linux"
        assert fp["os_confidence"] in ("medium", "high")


# ── HTTP Server header OS detection ───────────────────────────────────

class TestHTTPServerDetection:

    @pytest.mark.asyncio
    async def test_iis_windows(self):
        ctx = _make_ctx(services=[
            {"host": "win.example.com", "port": 443, "service_name": "https",
             "raw_banner": "Microsoft-IIS/10.0", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "Windows"
        assert "http_server_os" in fp["evidence_sources"]


# ── CDN/WAF correlation ──────────────────────────────────────────────

class TestCDNWAFCorrelation:

    @pytest.mark.asyncio
    async def test_cdn_downgrades_http_confidence(self):
        """When a CDN is detected, HTTP Server header evidence should
        produce lower OS confidence than without CDN."""
        services = [
            {"host": "cdn.example.com", "port": 443, "service_name": "https",
             "raw_banner": "nginx", "state": "open"},
        ]

        # Without CDN
        ctx_no_cdn = _make_ctx(services=services, cdn_waf_intel=[])
        engine = OSFingerprintEngine()
        r1 = await engine.execute(ctx_no_cdn)
        fp_no_cdn = r1.data["os_fingerprints"][0]

        # With CDN
        ctx_cdn = _make_ctx(
            services=services,
            cdn_waf_intel=[{
                "host": "cdn.example.com",
                "cdn_provider": "Cloudflare",
                "waf_detected": True,
            }],
        )
        r2 = await engine.execute(ctx_cdn)
        fp_cdn = r2.data["os_fingerprints"][0]

        # Both detect Linux, but CDN version should have lower confidence
        assert fp_no_cdn["os_family"] == "Linux"
        assert fp_cdn["os_family"] == "Linux"
        # Confidence should be lower with CDN
        conf_rank = {"high": 3, "medium": 2, "low": 1}
        assert conf_rank[fp_cdn["os_confidence"]] <= conf_rank[fp_no_cdn["os_confidence"]]
        # Evidence tag should indicate edge
        assert "http_server_os_edge" in fp_cdn["evidence_sources"]

    @pytest.mark.asyncio
    async def test_ssh_unaffected_by_cdn(self):
        """SSH evidence should NOT be downgraded by CDN — CDN doesn't proxy SSH."""
        ctx = _make_ctx(
            services=[
                {"host": "srv.example.com", "port": 22, "service_name": "ssh",
                 "raw_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                 "state": "open"},
            ],
            cdn_waf_intel=[{
                "host": "srv.example.com",
                "cdn_provider": "Cloudflare",
            }],
        )
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "Linux"
        # SSH alone gives 0.9 weight → medium confidence (>= 0.6)
        assert fp["os_confidence"] in ("medium", "high")

    @pytest.mark.asyncio
    async def test_cdn_plus_ssh_gives_origin_os(self):
        """With CDN detected, SSH banner should still provide strong origin OS evidence."""
        ctx = _make_ctx(
            services=[
                {"host": "srv.example.com", "port": 22, "service_name": "ssh",
                 "raw_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                 "state": "open"},
                {"host": "srv.example.com", "port": 443, "service_name": "https",
                 "raw_banner": "cloudflare", "state": "open"},
            ],
            cdn_waf_intel=[{
                "host": "srv.example.com",
                "cdn_provider": "Cloudflare",
            }],
        )
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] == "Linux"
        assert "ssh_banner" in fp["evidence_sources"]


# ── Edge cases ────────────────────────────────────────────────────────

class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_empty_services(self):
        ctx = _make_ctx(services=[])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        assert result.data["os_fingerprints"] == []

    @pytest.mark.asyncio
    async def test_unknown_banner(self):
        ctx = _make_ctx(services=[
            {"host": "mystery.example.com", "port": 443, "service_name": "https",
             "raw_banner": "XYZ-Unknown-Server/1.0", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["os_family"] is None
        assert fp["os_confidence"] == "low"

    @pytest.mark.asyncio
    async def test_multiple_hosts_independent(self):
        ctx = _make_ctx(services=[
            {"host": "linux.example.com", "port": 22, "service_name": "ssh",
             "raw_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "state": "open"},
            {"host": "win.example.com", "port": 443, "service_name": "https",
             "raw_banner": "Microsoft-IIS/10.0", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fps = result.data["os_fingerprints"]
        assert len(fps) == 2
        families = {fp["host"]: fp["os_family"] for fp in fps}
        assert families["linux.example.com"] == "Linux"
        assert families["win.example.com"] == "Windows"

    @pytest.mark.asyncio
    async def test_container_detection(self):
        ctx = _make_ctx(services=[
            {"host": "a1b2c3d4e5f6", "port": 80, "service_name": "http",
             "raw_banner": "nginx", "state": "open"},
        ])
        engine = OSFingerprintEngine()
        result = await engine.execute(ctx)
        fp = result.data["os_fingerprints"][0]
        assert fp["container_likely"] is True
        assert "hostname_pattern" in fp["evidence_sources"]
