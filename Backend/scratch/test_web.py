import asyncio
import logging
from app.scanner.engines.web_discovery import WebAPIDiscoveryEngine
from app.scanner.pipeline import ScanContext, ScanThrottle

logging.basicConfig(level=logging.DEBUG)

async def test_web():
    engine = WebAPIDiscoveryEngine()
    ctx = ScanContext(
        scan_id="test",
        target="example.com",
    )
    ctx.throttle = ScanThrottle()
    # Give it a service to trigger host acquisition
    ctx.services = [{"host": "example.com", "port": 443, "protocol_category": "web"}]
    
    result = await engine.execute(ctx)
    print("Result:", result)

if __name__ == "__main__":
    asyncio.run(test_web())
