"""
QuantumShield — MongoDB Connection

Async MongoDB client using Motor. Manages connection lifecycle
through the FastAPI lifespan context.
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

_client: AsyncIOMotorClient | None = None
_database: AsyncIOMotorDatabase | None = None


async def _ensure_mongodb_running() -> None:
    """Attempt to start the MongoDB service if connecting locally."""
    if "localhost" in settings.MONGO_URI or "127.0.0.1" in settings.MONGO_URI:
        import platform
        import asyncio
        system = platform.system()
        
        try:
            if system == "Windows":
                logger.info("Attempting to auto-start MongoDB service (Windows)...")
                # 'net start MongoDB' requires admin rights
                proc = await asyncio.create_subprocess_exec(
                    "net", "start", "MongoDB",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            elif system == "Linux":
                logger.info("Attempting to auto-start MongoDB service (Linux/Kali)...")
                # Use systemctl for Kali/Debian based systems
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "systemctl", "start", "mongod",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                return

            stdout, stderr = await proc.communicate()
            out = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
            
            if proc.returncode == 0:
                logger.info("✅ MongoDB service started successfully (or was already running).")
            elif "already been started" in out or "Active: active" in out:
                logger.info("✅ MongoDB service is already running.")
            else:
                logger.debug("MongoDB auto-start returned non-zero (may require privileges). Output: %s", out.strip())
        except Exception as e:
            logger.debug("Could not automate MongoDB startup: %s", e)


async def connect_db() -> None:
    """Establish the MongoDB connection. Gracefully handles unavailable DB."""
    global _client, _database
    
    await _ensure_mongodb_running()
    
    logger.info("Connecting to MongoDB at %s ...", settings.MONGO_URI)
    try:
        _client = AsyncIOMotorClient(
            settings.MONGO_URI,
            serverSelectionTimeoutMS=5000,
        )
        _database = _client[settings.MONGO_DB_NAME]
        # Verify connectivity
        await _client.admin.command("ping")
        logger.info("MongoDB connection established — database: %s", settings.MONGO_DB_NAME)
    except Exception as exc:
        logger.warning("⚠️  MongoDB unavailable (%s). App will start but scan storage will fail.", exc)
        _client = None
        _database = None


async def disconnect_db() -> None:
    """Close the MongoDB connection."""
    global _client, _database
    if _client:
        _client.close()
        _client = None
        _database = None
        logger.info("MongoDB connection closed.")


def get_database() -> AsyncIOMotorDatabase:
    """Return the active database handle. Raises if not connected."""
    if _database is None:
        raise RuntimeError("Database not initialised — call connect_db() first.")
    return _database
