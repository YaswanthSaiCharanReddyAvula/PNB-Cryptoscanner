"""
QuantumShield — Asset Inventory Endpoint

GET /api/asset-inventory → list IPv4/port/ASN/location records
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import AssetInventoryOut

router = APIRouter(tags=["Asset Inventory"])


@router.get(
    "/asset-inventory",
    response_model=List[AssetInventoryOut],
    summary="List detailed asset inventory records (IP, ports, ASN, location)",
)
async def list_asset_inventory(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """Return detailed inventory records including IP, ports, subnets, ASN, and location."""
    result = await session.execute(select(pg_models.AssetInventory))
    records = result.scalars().all()
    return [AssetInventoryOut.model_validate(r) for r in records]
