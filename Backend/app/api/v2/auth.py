"""
QuantumShield — Auth Endpoints

POST /api/login           → authenticate and return JWT
POST /api/forgot-password → generate password reset token
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    verify_password,
    create_access_token,
    generate_reset_token,
    hash_password,
)
from app.core.deps import get_pg_session
from app.db import pg_models
from app.schemas.schemas import LoginRequest, TokenResponse, ForgotPasswordRequest, ForgotPasswordResponse

router = APIRouter(tags=["Auth"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT access token",
)
async def login(
    body: LoginRequest,
    session: AsyncSession = Depends(get_pg_session),
):
    """Authenticate with email + password and receive a Bearer JWT token."""
    result = await session.execute(
        select(pg_models.User).where(pg_models.User.email == body.email)
    )
    user = result.scalars().first()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )

    token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=token, token_type="bearer", role=user.role)


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Initiate a password reset",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    session: AsyncSession = Depends(get_pg_session),
):
    """
    Generate a password-reset token for the user's email.
    In production this would send an email; here we store the token
    and return a generic message (no oracle for valid emails).
    """
    result = await session.execute(
        select(pg_models.User).where(pg_models.User.email == body.email)
    )
    user = result.scalars().first()

    if user:
        token = generate_reset_token()
        user.reset_token = token
        user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await session.commit()
        # In production → send email here

    return ForgotPasswordResponse(
        message="If that email is registered, a reset link has been sent."
    )
