import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def main():
    print("Connecting to MongoDB...")
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    
    # Verify connection
    await client.server_info()
    print("Connected.")
    
    # Drop the database
    db_name = "quantumshield"
    print(f"Dropping database '{db_name}'...")
    await client.drop_database(db_name)
    print(f"Database '{db_name}' successfully dropped. All existing scans have been cleared.")

if __name__ == "__main__":
    asyncio.run(main())
