"""
QuantumShield — Name Servers Endpoint

GET /api/nameservers → list all DNS name server records
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import NameServerOut

router = APIRouter(tags=["Name Servers"])


@router.get(
    "/nameservers",
    response_model=List[NameServerOut],
    summary="List all DNS name server records",
)
async def list_nameservers(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """Return all name server / DNS records stored in the system."""
    result = await session.execute(select(pg_models.NameServer))
    records = result.scalars().all()
    return [NameServerOut.model_validate(r) for r in records]
