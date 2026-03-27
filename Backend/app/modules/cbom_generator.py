"""
QuantumShield — CBOM Generator

Generates a structured Cryptographic Bill of Materials (CBOM)
from scan results, suitable for JSON export and reporting.
"""

from collections import Counter
from datetime import datetime
from typing import List

from app.db.models import CBOMReport, CryptoComponent, RiskLevel, ScanResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


def generate_cbom(scan_result: ScanResult) -> CBOMReport:
    """
    Aggregate all cryptographic components from a scan into a
    structured CBOM report.

    The report includes:
      - Deduplicated component list
      - Total component count
      - Risk summary (count per risk level)

    Args:
        scan_result: A completed ScanResult with cbom components.

    Returns:
        CBOMReport ready for JSON serialisation.
    """
    components = scan_result.cbom or []

    # Deduplicate by (host, name, category) — keep the highest risk entry
    unique: dict[tuple[str, str, str], CryptoComponent] = {}
    for comp in components:
        key = (comp.host or "", comp.name, comp.category.value)
        existing = unique.get(key)
        if existing is None or _risk_rank(comp.risk_level) > _risk_rank(existing.risk_level):
            unique[key] = comp

    deduped: List[CryptoComponent] = list(unique.values())

    # Risk summary
    risk_counter: Counter = Counter()
    for comp in deduped:
        risk_counter[comp.risk_level.value] += 1

    risk_summary = {level.value: risk_counter.get(level.value, 0) for level in RiskLevel}

    report = CBOMReport(
        schema_version="1.0.0",
        domain=scan_result.domain,
        generated_at=datetime.utcnow(),
        total_components=len(deduped),
        components=deduped,
        risk_summary=risk_summary,
    )

    logger.info(
        "CBOM generated for %s — %d unique components, risk breakdown: %s",
        scan_result.domain,
        report.total_components,
        risk_summary,
    )
    return report


def _risk_rank(level: RiskLevel) -> int:
    """Numeric rank for risk comparison (higher = more severe)."""
    return {
        RiskLevel.SAFE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }.get(level, 0)
