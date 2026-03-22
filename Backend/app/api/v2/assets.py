"""
QuantumShield — Assets Endpoint

GET /api/assets → paginated, filterable asset list
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import AssetListResponse, AssetOut

router = APIRouter(tags=["Assets"])


@router.get(
    "/assets",
    response_model=AssetListResponse,
    summary="List all assets with optional filtering and pagination",
)
async def list_assets(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    risk: Optional[str] = Query(default=None, description="Filter by risk level"),
    type: Optional[str] = Query(default=None, description="Filter by asset type"),
    search: Optional[str] = Query(default=None, description="Search by asset name or URL"),
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """Return a paginated list of assets. Supports filtering by risk, type, and search query."""
    query = select(pg_models.Asset)

    if risk:
        query = query.where(pg_models.Asset.risk == risk)
    if type:
        query = query.where(pg_models.Asset.type == type)
    if search:
        like = f"%{search}%"
        query = query.where(
            pg_models.Asset.asset_name.ilike(like) | pg_models.Asset.url.ilike(like)
        )

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar_one()

    # Paginate
    offset = (page - 1) * page_size
    result = await session.execute(query.offset(offset).limit(page_size))
    items = result.scalars().all()

    return AssetListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[AssetOut.model_validate(a) for a in items],
    )
