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

    # Demo tokens are not JWTs — must run before decode_access_token (which always fails on them)
    if token.startswith("demo-token-"):
        parts = token.split("-")
        uname = parts[2] if len(parts) > 2 else "user"
        if uname == "scanner":
            return User(
                id="demo-user-scanner",
                email="scanner@example.com",
                full_name="Scanner Operator",
                hashed_password="",
                role="admin",
            )
        return User(
            id=f"demo-user-{uname}",
            email=f"{uname}@pnb.bank.in",
            full_name=uname.capitalize(),
            hashed_password="",
            role="admin" if uname == "admin" else "employee",
        )

    user_id = decode_access_token(token)
    if not user_id:
        raise credentials_exception

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


async def require_employee_only(
    current_user: User = Depends(get_current_user),
) -> User:
    """Only the employee role may send in-app messages to administrators."""
    if current_user.role.lower() != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employee accounts can send notifications to administrators.",
        )
    return current_user
