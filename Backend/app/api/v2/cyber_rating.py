"""
QuantumShield — Cyber Rating Endpoint

GET /api/cyber-rating → overall security score and risk factor breakdown
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import CyberRating, RiskFactor

router = APIRouter(tags=["Cyber Rating"])

_GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D")]


def _grade(score: int) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


@router.get(
    "/cyber-rating",
    response_model=CyberRating,
    summary="Return an overall cyber security rating score",
)
async def cyber_rating(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """
    Compute a 0-100 cyber security rating from asset risk levels and
    certificate statuses. Includes a list of concrete risk factors.
    """
    result = await session.execute(select(pg_models.Asset))
    assets = result.scalars().all()

    risk_factors: list[RiskFactor] = []
    deductions = 0

    for asset in assets:
        # Risk deductions
        if asset.risk == "critical":
            deductions += 10
            risk_factors.append(RiskFactor(
                factor=f"Critical-risk asset: {asset.asset_name}",
                severity="critical",
                detail="Asset classified as critical risk — immediate remediation required.",
            ))
        elif asset.risk == "high":
            deductions += 5
            risk_factors.append(RiskFactor(
                factor=f"High-risk asset: {asset.asset_name}",
                severity="high",
                detail="Asset has high-risk cryptographic configuration.",
            ))

        # Certificate deductions
        if asset.certificate_status == "expired":
            deductions += 8
            risk_factors.append(RiskFactor(
                factor=f"Expired certificate: {asset.asset_name}",
                severity="critical",
                detail="TLS certificate has expired — traffic is unprotected.",
            ))
        elif asset.certificate_status == "expiring_soon":
            deductions += 3
            risk_factors.append(RiskFactor(
                factor=f"Certificate expiring soon: {asset.asset_name}",
                severity="medium",
                detail="Certificate expires within 30 days.",
            ))

        # Weak key deductions
        if asset.key_length and asset.key_length < 2048:
            deductions += 7
            risk_factors.append(RiskFactor(
                factor=f"Weak key on {asset.asset_name} ({asset.key_length}-bit)",
                severity="high",
                detail="Key length below 2048-bit RSA is considered cryptographically weak.",
            ))

    score = max(0, 100 - deductions)
    return CyberRating(
        score=score,
        grade=_grade(score),
        risk_factors=risk_factors,
    )
