"""
QuantumShield — FastAPI Application Entry Point

Sets up the app, CORS middleware, MongoDB lifespan, PostgreSQL lifespan,
rate limiting, and API routing.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.db.connection import connect_db, disconnect_db
from app.api.routes import router as scanner_router          # v1 scanner & all dashboard endpoints
from app.api.v1.ws import router as ws_router               # real-time scan updates
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Rate limiter ─────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ── Lifespan: connect / disconnect both DBs ──────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events for MongoDB and PostgreSQL."""
    logger.info("🚀 Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)

    # MongoDB (existing scanner pipeline)
    await connect_db()

    yield

    await disconnect_db()
    logger.info("🛑 %s shut down.", settings.APP_NAME)


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global exception handler ────────────────────────────────────

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

# Scanner routes & all dashboard endpoints
app.include_router(scanner_router, prefix="/api/v1")

# WebSocket scan updates
app.include_router(ws_router)


# ── Health check ─────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
