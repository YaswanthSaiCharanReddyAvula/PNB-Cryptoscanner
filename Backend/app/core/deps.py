"""
QuantumShield — FastAPI Dependencies

get_current_user  → any authenticated user
require_admin     → admin-only guard
require_employee  → admin or employee guard
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.postgres import get_pg_session
from app.db import pg_models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_pg_session),
) -> pg_models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_id = decode_access_token(token)
    if not user_id:
        raise credentials_exception

    result = await session.execute(
        select(pg_models.User).where(pg_models.User.id == user_id)
    )
    user = result.scalars().first()
    if not user or not user.is_active:
        raise credentials_exception
    return user


async def require_admin(
    current_user: pg_models.User = Depends(get_current_user),
) -> pg_models.User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


async def require_employee(
    current_user: pg_models.User = Depends(get_current_user),
) -> pg_models.User:
    if current_user.role not in ("admin", "employee"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Employee or Admin access required.",
        )
    return current_user
