"""
QuantumShield — Dashboard Endpoint

GET /api/dashboard/summary → aggregate counts across all assets
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import DashboardSummary

router = APIRouter(tags=["Dashboard"])


@router.get(
    "/dashboard/summary",
    response_model=DashboardSummary,
    summary="Return high-level counts for the home dashboard",
)
async def dashboard_summary(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """
    Aggregate asset counts, expiring certificate alerts, and high-risk
    asset count from the PostgreSQL database.
    """
    # Total assets
    total = (await session.execute(select(func.count()).select_from(pg_models.Asset))).scalar_one()

    # Web apps
    web_apps = (await session.execute(
        select(func.count()).select_from(pg_models.Asset).where(pg_models.Asset.type == "web_app")
    )).scalar_one()

    # APIs
    apis = (await session.execute(
        select(func.count()).select_from(pg_models.Asset).where(pg_models.Asset.type == "api")
    )).scalar_one()

    # Servers
    servers = (await session.execute(
        select(func.count()).select_from(pg_models.Asset).where(pg_models.Asset.type == "server")
    )).scalar_one()

    # Expiring / expired certs
    expiring_certs = (await session.execute(
        select(func.count()).select_from(pg_models.Asset).where(
            pg_models.Asset.certificate_status.in_(["expiring_soon", "expired"])
        )
    )).scalar_one()

    # High-risk (critical or high)
    high_risk = (await session.execute(
        select(func.count()).select_from(pg_models.Asset).where(
            pg_models.Asset.risk.in_(["critical", "high"])
        )
    )).scalar_one()

    return DashboardSummary(
        total_assets=total,
        public_web_apps=web_apps,
        apis=apis,
        servers=servers,
        expiring_certificates=expiring_certs,
        high_risk_assets=high_risk,
    )
