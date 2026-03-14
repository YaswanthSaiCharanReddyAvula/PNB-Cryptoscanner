"""
QuantumShield — FastAPI Application Entry Point

Sets up the app, CORS middleware, MongoDB lifespan, and API routing.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.connection import connect_db, disconnect_db
from app.api.routes import router as api_router
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Lifespan: connect / disconnect MongoDB ───────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events."""
    logger.info("🚀 Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    await connect_db()
    yield
    await disconnect_db()
    logger.info("🛑 %s shut down.", settings.APP_NAME)


# ── Application ──────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Quantum-Proof Cryptographic Scanner for Banking Systems. "
        "Scans TLS configurations, builds a Cryptographic Bill of Materials (CBOM), "
        "evaluates quantum readiness, and recommends PQC migration paths."
    ),
    lifespan=lifespan,
)


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

app.include_router(api_router, prefix="/api/v1")


# ── Health check ─────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
