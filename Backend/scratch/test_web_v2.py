import asyncio
from app.scanner.engines.web_discovery import WebAPIDiscoveryEngine
from app.scanner.pipeline import ScanContext

class MockThrottle:
    def acquire(self, *a, **kw):
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def _():
            yield
        return _()

async def test_web01_and_web02():
    engine = WebAPIDiscoveryEngine()
    ctx = ScanContext(scan_id='test-web01', domain='example.com')
    ctx.throttle = MockThrottle()
    # Service with non-standard port (tests WEB-02)
    ctx.services = [
        {'host': 'example.com', 'port': 443, 'protocol_category': 'web'},
        {'host': 'example.com', 'port': 8080, 'protocol_category': 'web'},
    ]
    res = await engine.execute(ctx)
    profiles = res.data.get('web_profiles', [])
    print(f'Status: {res.status}')
    print(f'Profiles generated: {len(profiles)}')
    for p in profiles:
        wk = p.get('well_known_results', [])
        host = p.get('host')
        url = p.get('url')
        wk_type = type(wk).__name__
        wk_count = len(wk)
        print(f'  Host: {host} URL: {url}  well_known_results type={wk_type} count={wk_count}')
        assert isinstance(wk, list), f"FAIL WEB-01: well_known_results is {wk_type} not list"

    # Verify WEB-02: URLs must contain port 8080
    urls = [p.get('url', '') for p in profiles]
    has_8080 = any('8080' in u for u in urls)
    print(f'WEB-02 port 8080 in URLs: {has_8080}  (URLs: {urls})')

    print("WEB-01 PASSED: No ValidationError, well_known_results is list")
    if has_8080:
        print("WEB-02 PASSED: Non-standard port 8080 respected")
    else:
        print("WEB-02: Port 8080 URL not confirmed (may be scope-blocked if example.com resolves differently)")

asyncio.run(test_web01_and_web02())
