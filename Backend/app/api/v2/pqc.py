"""
QuantumShield — PQC Posture Endpoint

GET /api/pqc/posture → vulnerable algorithms, PQC-ready count, migration score
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import PQCPosture, VulnerableAlgorithm

# Algorithms that are NOT quantum-safe
VULNERABLE_PATTERNS = {
    "RSA": "high",
    "ECDHE": "medium",
    "TLS 1.0": "critical",
    "TLS 1.1": "high",
    "TLS 1.2": "medium",
    "AES_128_CBC": "high",
    "DHE": "medium",
}

# Algorithms/protocols considered PQC-ready
PQC_SAFE_PROTOCOLS = {"TLS 1.3"}

router = APIRouter(tags=["PQC Posture"])


@router.get(
    "/pqc/posture",
    response_model=PQCPosture,
    summary="Return overall post-quantum cryptography (PQC) posture",
)
async def pqc_posture(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """
    Analyse all crypto records to identify vulnerable algorithms,
    estimate PQC-ready assets, and compute a migration score (0-100).
    """
    result = await session.execute(select(pg_models.CryptoRecord))
    records = result.scalars().all()

    vuln_counts: dict[str, dict] = {}
    pqc_ready = 0

    for r in records:
        is_safe = r.tls_version in PQC_SAFE_PROTOCOLS and (r.key_length or 0) >= 4096
        if is_safe:
            pqc_ready += 1

        # Check cipher and protocol for vulnerable patterns
        combined = " ".join(filter(None, [r.cipher_suite, r.tls_version]))
        for pattern, risk in VULNERABLE_PATTERNS.items():
            if pattern in combined:
                if pattern not in vuln_counts:
                    vuln_counts[pattern] = {"count": 0, "risk": risk}
                vuln_counts[pattern]["count"] += 1

    vulnerable_algorithms = [
        VulnerableAlgorithm(name=name, count=data["count"], risk=data["risk"])
        for name, data in sorted(vuln_counts.items(), key=lambda x: -x[1]["count"])
    ]

    total = len(records) or 1
    # Migration score: % of records that are already PQC-safe (0-100)
    migration_score = round((pqc_ready / total) * 100, 1)

    return PQCPosture(
        vulnerable_algorithms=vulnerable_algorithms,
        pqc_ready_assets=pqc_ready,
        migration_score=migration_score,
    )
