import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_db():
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["pnb_crypto_scanner"]
    
    # Check latest completed scan
    doc = await db["scans"].find_one({"status": "completed"}, sort=[("completed_at", -1)])
    if not doc:
        print("No completed scans found.")
        return
    
    print(f"Latest scan: {doc.get('domain')} at {doc.get('completed_at')}")
    print(f"Fields available: {list(doc.keys())}")
    
    cbom = doc.get("cbom")
    if cbom:
        print(f"CBOM components: {len(cbom.get('components', []))}")
    else:
        print("CBOM field is missing.")
        
    intel = doc.get("asset_intelligence")
    if intel:
        print(f"Asset Intelligence records: {len(intel)}")
    else:
        print("Asset Intelligence field is missing.")

if __name__ == "__main__":
    asyncio.run(check_db())
