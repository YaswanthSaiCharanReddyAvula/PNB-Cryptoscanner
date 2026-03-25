"""
QuantumShield — FastAPI Dependencies

get_current_user  → any authenticated user
require_admin     → admin-only guard
require_employee  → admin or employee guard
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.security import decode_access_token
from app.db.connection import get_database
from app.db.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

USERS_COLLECTION = "users"


async def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_id = decode_access_token(token)
    if not user_id:
        raise credentials_exception

    # For hackathon demo, if token is "demo-token-...", we can bypass DB or return a mock
    if token.startswith("demo-token-"):
        username = token.split("-")[2]
        return User(
            email=f"{username}@pnb.bank.in",
            full_name=username.capitalize(),
            hashed_password="",
            role="admin" if username == "admin" else "employee",
        )

    db = get_database()
    user_doc = await db[USERS_COLLECTION].find_one({"id": user_id})
    if not user_doc or not user_doc.get("is_active", True):
        raise credentials_exception
    
    return User(**user_doc)


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role.lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


async def require_employee(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role.lower() not in ("admin", "employee"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Employee or Admin access required.",
        )
    return current_user
