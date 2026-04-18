import asyncio
import json
from motor.motor_asyncio import AsyncIOMotorClient

async def run():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['quantumshield']
    
    # Get all scans
    scans = await db['scans'].find({"status": "completed"}).to_list(length=10)
    for scan in scans:
        domain = scan.get("domain")
        cbom = scan.get("cbom_report", {})
        components = cbom.get("components", [])
        print(f"Domain: {domain}, Components: {len(components)}")

asyncio.run(run())
