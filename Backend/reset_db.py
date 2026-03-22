import asyncio
import sys
import os

sys.path.append(os.getcwd())

from app.db.postgres import engine, Base
from app.db import pg_models
from app.db.init_db import init_db

async def reset():
    print("Dropping all PostgreSQL tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("Re-initializing DB (this will create tables and the admin user without the dummy data)...")
    await init_db()
    print("PostgreSQL Database Reset Completed.")

if __name__ == "__main__":
    asyncio.run(reset())
