"""
QuantumShield — FastAPI Application Entry Point

Sets up the app, CORS middleware, MongoDB lifespan, PostgreSQL lifespan,
rate limiting, and API routing.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.db.connection import (
    DatabaseUnavailableError,
    connect_db,
    disconnect_db,
    get_database,
)
from app.api.routes import router as scanner_router          # v1 scanner & all dashboard endpoints
from app.api.v1.ws import router as ws_router               # real-time scan updates
from app.utils.logger import get_logger
from app.modules.report_scheduler import scheduler_loop

logger = get_logger(__name__)

# Private / dev browser origins when .env is mis-quoted (non-wildcard list).
# Starlette matches this after allow_origins; mirrors Access-Control-Allow-Origin.
_CORS_DEV_LAN_REGEX = (
    r"^https?://("
    r"localhost|127\.0\.0\.1|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r")(?::\d+)?$"
)

# ── Rate limiter ─────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ── Background: terminal scan retention purge ───────────────────

async def scan_retention_loop(stop: asyncio.Event) -> None:
    """Periodically delete terminal scans older than SCAN_RETENTION_DAYS."""
    from app.modules.scan_lifecycle import purge_expired_scans

    while not stop.is_set():
        try:
            db = get_database()
            await purge_expired_scans(db)
        except DatabaseUnavailableError:
            pass
        except Exception as exc:
            logger.exception("Scan retention purge failed: %s", exc)
        try:
            await asyncio.wait_for(
                stop.wait(),
                timeout=float(max(60, settings.SCAN_PURGE_INTERVAL_SECONDS)),
            )
        except asyncio.TimeoutError:
            pass


# ── Lifespan: connect / disconnect MongoDB ───────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events for MongoDB."""
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)

    # MongoDB (existing scanner pipeline)
    await connect_db()

    stop_scheduler = asyncio.Event()
    sched_task = asyncio.create_task(scheduler_loop(stop_scheduler))

    stop_retention = asyncio.Event()
    retention_task = asyncio.create_task(scan_retention_loop(stop_retention))

    yield

    stop_scheduler.set()
    stop_retention.set()
    sched_task.cancel()
    retention_task.cancel()
    try:
        await sched_task
    except asyncio.CancelledError:
        pass
    try:
        await retention_task
    except asyncio.CancelledError:
        pass

    await disconnect_db()
    logger.info("%s shut down.", settings.APP_NAME)


# ── Application ──────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Quantum-Safe Cryptography Assessment System for Banking. "
        "Scans TLS configurations, builds a CBOM, evaluates quantum readiness, "
        "provides PQC migration paths, and serves a comprehensive security dashboard."
    ),
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── CORS ─────────────────────────────────────────────────────────
# CORS_ORIGINS=* allows any Origin; allow_credentials must be False for wildcard.

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=_CORS_DEV_LAN_REGEX,
)


# ── Global exception handlers ───────────────────────────────────

@app.exception_handler(DatabaseUnavailableError)
async def database_unavailable_handler(request: Request, exc: DatabaseUnavailableError):
    """MongoDB not connected — return 503 instead of a generic 500."""
    logger.warning("Database unavailable on %s %s: %s", request.method, request.url, exc)
    return JSONResponse(
        status_code=503,
        content={
            "error": "database_unavailable",
            "detail": str(exc),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions and return a structured JSON error."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": "An unexpected error occurred. Please try again later.",
        },
    )


# ── Routes ───────────────────────────────────────────────────────

# Scanner routes & all dashboard endpoints (v1)
app.include_router(scanner_router, prefix="/api/v1")

# WebSocket scan updates
app.include_router(ws_router)



# ── Health check ─────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check(wipe: bool = False):
    """Simple health check endpoint. If wipe=true, clear MongoDB."""
    mongo_status = "N/A"
    try:
        get_database()
        mongodb = "connected"
    except DatabaseUnavailableError:
        mongodb = "disconnected"

    if wipe:
        logger.warning("🚨 SYSTEM WIPE TRIGGERED VIA HEALTH CHECK")
        try:
            db = get_database()
            collections = await db.list_collection_names()
            for coll in collections:
                await db[coll].delete_many({})
            mongo_status = "Success"
        except DatabaseUnavailableError as e:
            mongo_status = f"Error: {e}"
        except Exception as e:
            mongo_status = f"Error: {e}"

    return {
        "status": "healthy" if mongodb == "connected" else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "mongodb": mongodb,
        "wipe_status": {
            "mongodb": mongo_status
        }
    }

