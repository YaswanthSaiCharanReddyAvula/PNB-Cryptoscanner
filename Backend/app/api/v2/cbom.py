"""
QuantumShield — CBOM Endpoints

GET /api/cbom/summary → aggregate counts
GET /api/cbom/charts  → distribution data for key lengths, CAs, protocols
"""

from __future__ import annotations

from collections import Counter
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import (
    CBOMSummaryOut,
    CBOMCharts,
    KeyLengthDist,
    CADist,
    ProtocolDist,
)

router = APIRouter(tags=["CBOM"])


@router.get(
    "/cbom/summary",
    response_model=CBOMSummaryOut,
    summary="Return CBOM aggregate statistics",
)
async def cbom_summary(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """Return the latest Cryptographic Bill of Materials summary."""
    result = await session.execute(
        select(pg_models.CBOMSummary).order_by(pg_models.CBOMSummary.created_at.desc())
    )
    summary = result.scalars().first()
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No CBOM summary available yet.",
        )
    return CBOMSummaryOut(
        total_applications=summary.total_applications,
        sites_surveyed=summary.sites_surveyed,
        active_certificates=summary.active_certificates,
        weak_cryptography=summary.weak_cryptography,
        certificate_issues=summary.certificate_issues,
    )


@router.get(
    "/cbom/charts",
    response_model=CBOMCharts,
    summary="Return distribution data for CBOM charts",
)
async def cbom_charts(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """
    Aggregate key_length, certificate_authority, and tls_version distributions
    from all crypto records for chart rendering.
    """
    result = await session.execute(select(pg_models.CryptoRecord))
    records = result.scalars().all()

    key_counter: Counter = Counter()
    ca_counter: Counter = Counter()
    proto_counter: Counter = Counter()

    for r in records:
        if r.key_length:
            key_counter[r.key_length] += 1
        if r.certificate_authority:
            ca_counter[r.certificate_authority] += 1
        if r.tls_version:
            proto_counter[r.tls_version] += 1

    key_dist: List[KeyLengthDist] = [
        KeyLengthDist(key_length=k, count=v) for k, v in sorted(key_counter.items())
    ]
    ca_dist: List[CADist] = [
        CADist(certificate_authority=k, count=v)
        for k, v in ca_counter.most_common(10)
    ]
    proto_dist: List[ProtocolDist] = [
        ProtocolDist(tls_version=k, count=v)
        for k, v in proto_counter.most_common()
    ]

    return CBOMCharts(
        key_length_distribution=key_dist,
        top_certificate_authorities=ca_dist,
        encryption_protocols=proto_dist,
    )
