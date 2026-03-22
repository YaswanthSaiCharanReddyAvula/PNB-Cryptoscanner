import asyncio
import sys
import os

sys.path.append(os.getcwd())

from sqlalchemy import text
from app.db.postgres import engine, Base
from app.db import pg_models

async def clean():
    print("Deleting all sample data rows...")
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            if table.name != "users":
                await conn.execute(table.delete())
    print("Database sample data deleted.")

if __name__ == "__main__":
    asyncio.run(clean())
