import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def main():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['quantumshield']
    docs = await db.scans.find({'domain': 'testssl.sh'}).sort('_id', -1).limit(2).to_list(length=2)
    for doc in docs:
        print(f"Scan ID: {doc.get('scan_id')}")
        print(f"Status: {doc.get('status')}")
        print(f"Error: {doc.get('error')}")
        print('-'*40)

if __name__ == '__main__':
    asyncio.run(main())
