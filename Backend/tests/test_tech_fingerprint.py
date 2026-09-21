"""
Tests for TechFingerprintEngine — deduplication, runtime migration,
CPE generation, HTTP caching, and failure modes.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from app.scanner.engines.tech_fingerprint import (
    TechFingerprintEngine,
    _TechAccumulator,
    _load_signatures,
    BANNER_RUNTIME_SIGS,
    COOKIE_RUNTIME_MAP,
)
from app.scanner.pipeline import ScanContext


def _make_ctx(services=None, subdomains=None, http_cache=None):
    throttle = MagicMock()
    # Make throttle.acquire return an async context manager
    acm = AsyncMock()
    acm.__aenter__ = AsyncMock(return_value=None)
    acm.__aexit__ = AsyncMock(return_value=None)
    throttle.acquire = MagicMock(return_value=acm)
    ctx = ScanContext(
        scan_id="test-tech", domain="example.com", throttle=throttle,
    )
    ctx.services = services or []
    ctx.subdomains = subdomains or ["example.com"]
    if http_cache is not None:
        ctx.http_cache = http_cache
    return ctx


# ── Deduplication tests ───────────────────────────────────────────────

class TestTechAccumulator:

    def test_single_detection(self):
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                version="8.2", confidence="high", evidence="header: X-Powered-By")
        results = acc.results()
        assert len(results) == 1
        assert results[0]["name"] == "PHP"
        assert results[0]["version"] == "8.2"
        assert "header: X-Powered-By" in results[0]["evidence_sources"]

    def test_duplicate_merge(self):
        """Two detections of PHP should produce one record with merged evidence."""
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                version="8.2", confidence="high",
                evidence="header: X-Powered-By: PHP/8.2")
        acc.add(host="ex.com", category="language", name="PHP",
                confidence="medium", evidence="cookie PHPSESSID")
        results = acc.results()
        assert len(results) == 1
        assert results[0]["name"] == "PHP"
        assert results[0]["version"] == "8.2"
        assert results[0]["confidence"] == "high"  # best confidence
        assert len(results[0]["evidence_sources"]) == 2

    def test_version_promotion(self):
        """Versionless detection followed by versioned should keep the version."""
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                confidence="medium", evidence="cookie PHPSESSID")
        acc.add(host="ex.com", category="language", name="PHP",
                version="8.2", confidence="high",
                evidence="header X-Powered-By")
        results = acc.results()
        assert len(results) == 1
        assert results[0]["version"] == "8.2"

    def test_different_techs_not_merged(self):
        """PHP and Python should remain separate."""
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                version="8.2", evidence="header")
        acc.add(host="ex.com", category="language", name="Python",
                evidence="banner")
        results = acc.results()
        assert len(results) == 2
        names = {r["name"] for r in results}
        assert names == {"PHP", "Python"}

    def test_different_hosts_not_merged(self):
        """Same tech on different hosts should remain separate."""
        acc = _TechAccumulator()
        acc.add(host="a.example.com", category="web_server", name="nginx",
                evidence="header")
        acc.add(host="b.example.com", category="web_server", name="nginx",
                evidence="header")
        results = acc.results()
        assert len(results) == 2

    def test_cpe_preserved(self):
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                version="8.2", cpe="cpe:2.3:a:php:php:8.2",
                evidence="header")
        results = acc.results()
        assert results[0]["cpe"] == "cpe:2.3:a:php:php:8.2"

    def test_evidence_not_duplicated(self):
        """Same evidence string should not appear twice."""
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="language", name="PHP",
                evidence="cookie PHPSESSID")
        acc.add(host="ex.com", category="language", name="PHP",
                evidence="cookie PHPSESSID")
        results = acc.results()
        assert len(results[0]["evidence_sources"]) == 1


# ── Runtime migration tests ──────────────────────────────────────────

class TestRuntimeMigration:

    @pytest.mark.asyncio
    async def test_banner_php_detected_as_tech(self):
        """PHP in service banner should be detected by Tech engine, not OS."""
        ctx = _make_ctx(services=[
            {"host": "web.example.com", "port": 80, "service_name": "http",
             "raw_banner": "PHP/8.2.1", "state": "open",
             "protocol_category": "web"},
        ])
        engine = TechFingerprintEngine()
        acc = _TechAccumulator()
        engine._extract_banner_runtimes(ctx, acc)
        results = acc.results()
        php_results = [r for r in results if r["name"] == "PHP"]
        assert len(php_results) == 1
        assert php_results[0]["version"] == "8.2.1"
        assert php_results[0]["category"] == "language"

    @pytest.mark.asyncio
    async def test_banner_python_detected(self):
        ctx = _make_ctx(services=[
            {"host": "api.example.com", "port": 8000, "service_name": "http",
             "raw_banner": "uvicorn", "state": "open"},
        ])
        acc = _TechAccumulator()
        TechFingerprintEngine._extract_banner_runtimes(ctx, acc)
        results = acc.results()
        python_results = [r for r in results if r["name"] == "Python"]
        assert len(python_results) == 1

    @pytest.mark.asyncio
    async def test_banner_express_detected(self):
        ctx = _make_ctx(services=[
            {"host": "app.example.com", "port": 3000, "service_name": "http",
             "raw_banner": "Express", "state": "open"},
        ])
        acc = _TechAccumulator()
        TechFingerprintEngine._extract_banner_runtimes(ctx, acc)
        results = acc.results()
        express_results = [r for r in results if r["name"] == "Express/Node.js"]
        assert len(express_results) == 1


# ── CPE generation tests ─────────────────────────────────────────────

class TestCPEGeneration:

    def test_cpe_with_version(self):
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="web_server", name="nginx",
                version="1.24.0",
                cpe="cpe:2.3:a:nginx:nginx:1.24.0",
                evidence="header")
        results = acc.results()
        assert results[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24.0"

    def test_no_cpe_without_version(self):
        """When version is unknown, CPE should not be fabricated."""
        acc = _TechAccumulator()
        acc.add(host="ex.com", category="web_server", name="nginx",
                evidence="header")
        results = acc.results()
        assert results[0]["cpe"] is None


# ── HTTP cache tests ─────────────────────────────────────────────────

class TestHTTPCache:

    @pytest.mark.asyncio
    async def test_cache_prevents_duplicate_request(self):
        """Second fetch of the same URL should use cache."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.text = "<html></html>"
        mock_response.cookies = {}
        mock_response.status_code = 200

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_response)

        ctx = _make_ctx()
        url = "https://example.com/"

        # First call should make a request
        resp1, cached1 = await TechFingerprintEngine._fetch_or_cache(
            client, url, ctx
        )
        assert cached1 is False
        assert client.get.call_count == 1

        # Second call should use cache
        resp2, cached2 = await TechFingerprintEngine._fetch_or_cache(
            client, url, ctx
        )
        assert cached2 is True
        assert client.get.call_count == 1  # No additional request
        assert resp1 is resp2


# ── Failure mode tests ────────────────────────────────────────────────

class TestFailureModes:

    @pytest.mark.asyncio
    async def test_connect_error_graceful(self):
        import httpx
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        ctx = _make_ctx()
        resp, cached = await TechFingerprintEngine._fetch_or_cache(
            client, "https://unreachable.example.com/", ctx
        )
        assert resp is None
        assert cached is False

    @pytest.mark.asyncio
    async def test_empty_services_produces_empty(self):
        """Engine should not crash on empty services."""
        ctx = _make_ctx(services=[], subdomains=[])
        engine = TechFingerprintEngine()

        # Patch _load_signatures to return empty (no file needed)
        with patch("app.scanner.engines.tech_fingerprint._load_signatures", return_value=[]):
            result = await engine.execute(ctx)
        assert result.status == "completed"
        assert result.data.get("tech_fingerprints") == []

    def test_missing_signature_file_degraded(self):
        """When signatures fail to load, engine should operate in degraded mode."""
        import app.scanner.engines.tech_fingerprint as mod
        mod._sig_cache = None  # Reset cache

        with patch.object(Path, "is_file", return_value=False):
            sigs = _load_signatures()
        assert sigs == []

        # Reset for other tests
        mod._sig_cache = None


# ── Confidence aggregation tests ──────────────────────────────────────

class TestConfidence:

    def test_high_beats_medium(self):
        from app.scanner.engines.tech_fingerprint import _best_confidence
        assert _best_confidence("medium", "high") == "high"

    def test_medium_beats_low(self):
        from app.scanner.engines.tech_fingerprint import _best_confidence
        assert _best_confidence("low", "medium") == "medium"

    def test_same_confidence_stable(self):
        from app.scanner.engines.tech_fingerprint import _best_confidence
        assert _best_confidence("medium", "medium") == "medium"
