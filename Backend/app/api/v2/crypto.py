"""
QuantumShield — Crypto Security Endpoint

GET /api/crypto → list all cryptographic security records
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import CryptoRecordOut

router = APIRouter(tags=["Crypto Security"])


@router.get(
    "/crypto",
    response_model=List[CryptoRecordOut],
    summary="List all cryptographic security records",
)
async def list_crypto(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """Return all TLS/cipher records discovered across assets."""
    result = await session.execute(select(pg_models.CryptoRecord))
    records = result.scalars().all()
    return [CryptoRecordOut.model_validate(r) for r in records]
