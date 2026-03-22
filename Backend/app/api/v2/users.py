"""
QuantumShield — Users Endpoints

GET /api/users/me → return the authenticated user's profile
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.deps import get_current_user
from app.db import pg_models
from app.schemas.schemas import UserOut

router = APIRouter(tags=["Users"])


@router.get(
    "/users/me",
    response_model=UserOut,
    summary="Return the current authenticated user's profile",
)
async def get_me(
    current_user: pg_models.User = Depends(get_current_user),
):
    """Return profile information for the currently authenticated user."""
    return current_user
