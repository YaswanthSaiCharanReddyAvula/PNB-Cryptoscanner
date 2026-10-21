"""
QuantumShield — Phase 4.3 Regression Tests
Mosca Boundary Semantics and HNDL Timeline Modeling

Covers:
1. Mosca margin immediately below -2.
2. Mosca margin exactly equal to -2.
3. Mosca margin immediately above -2.
4. Existing Mosca classifications outside the boundary (-0.5, 0.0, +0.1, +5.0).
5. HNDL scoring across documented timeline values (Tc vs Tq).
6. HNDL behavior when timeline data is missing or invalid.
7. Sensitivity-level differences and strict monotonicity.
8. Interaction between HNDL results and quantum-risk aggregation.
9. Unknown or insufficient-evidence semantics in Mosca and HNDL.
10. Backward compatibility with Phase 4.1 and Phase 4.2 assets.
"""

import uuid
from datetime import datetime, timezone
import pytest

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalProperty,
    AssetType,
)
from app.scanner.quantum.models import (
    QuantumTimeline,
    TimeValue,
    MoscaAssessment,
    HNDLAssessment,
    QuantumRiskAssessment,
)
from app.scanner.quantum.mosca_engine import calculate_mosca_assessment
from app.scanner.quantum.hndl_engine import calculate_hndl_exposure, SENSITIVITY_WEIGHT
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.aggregation_engine import (
    aggregate_asset_risk,
    aggregate_organization_risk,
)


def _make_timeline(tm: float = 2.0, tc: float = 5.0, tq: float = 15.0) -> QuantumTimeline:
    return QuantumTimeline(
        Tm=TimeValue(value=tm, unit="years", source="test", confidence=0.8),
        Tc=TimeValue(value=tc, unit="years", source="test", confidence=0.8),
        Tq=TimeValue(value=tq, unit="years", source="test", confidence=0.8),
    )


# =========================================================================
# 1. Mosca margin immediately below -2
# =========================================================================

def test_mosca_margin_immediately_below_minus_two():
    """Verify margin < -2 resolves to SAFE_MARGIN."""
    # margin = 3 + 9.9 - 15 = -2.1
    t1 = _make_timeline(tm=3.0, tc=9.9, tq=15.0)
    m1 = calculate_mosca_assessment(t1)
    assert m1.margin == pytest.approx(-2.1)
    assert m1.status == "SAFE_MARGIN"

    # margin = 2 + 5 - 10 = -3.0
    t2 = _make_timeline(tm=2.0, tc=5.0, tq=10.0)
    m2 = calculate_mosca_assessment(t2)
    assert m2.margin == pytest.approx(-3.0)
    assert m2.status == "SAFE_MARGIN"

    # margin = -2.0001
    t3 = _make_timeline(tm=3.0, tc=9.9999, tq=15.0)
    m3 = calculate_mosca_assessment(t3)
    assert m3.margin < -2.0
    assert m3.status == "SAFE_MARGIN"


# =========================================================================
# 2. Mosca margin exactly equal to -2
# =========================================================================

def test_mosca_margin_exactly_minus_two():
    """Verify margin == -2.0 resolves to SAFE_MARGIN (fixing the boundary discrepancy)."""
    # Canonical test vector: Tm=3, Tc=10, Tq=15 -> margin = -2.0
    t1 = _make_timeline(tm=3.0, tc=10.0, tq=15.0)
    m1 = calculate_mosca_assessment(t1)
    assert m1.margin == -2.0
    assert m1.status == "SAFE_MARGIN"

    # Zero-based vector: Tm=0, Tc=0, Tq=2 -> margin = -2.0
    t2 = _make_timeline(tm=0.0, tc=0.0, tq=2.0)
    m2 = calculate_mosca_assessment(t2)
    assert m2.margin == -2.0
    assert m2.status == "SAFE_MARGIN"


# =========================================================================
# 3. Mosca margin immediately above -2
# =========================================================================

def test_mosca_margin_immediately_above_minus_two():
    """Verify margin slightly above -2 (e.g. -1.9, -1.9999) transitions into BORDERLINE."""
    # margin = 3 + 10.1 - 15 = -1.9
    t1 = _make_timeline(tm=3.0, tc=10.1, tq=15.0)
    m1 = calculate_mosca_assessment(t1)
    assert m1.margin == pytest.approx(-1.9)
    assert m1.status == "BORDERLINE"

    # margin = 3 + 10.0001 - 15 = -1.9999
    t2 = _make_timeline(tm=3.0, tc=10.0001, tq=15.0)
    m2 = calculate_mosca_assessment(t2)
    assert m2.margin > -2.0
    assert m2.margin < 0.0
    assert m2.status == "BORDERLINE"


# =========================================================================
# 4. Existing Mosca classifications outside the boundary
# =========================================================================

def test_existing_mosca_classifications_outside_boundary():
    """Verify all existing Mosca regions remain preserved: BORDERLINE, MIGRATION_REQUIRED, CRITICAL_URGENCY."""
    # BORDERLINE: -2 < margin < 0
    t_borderline = _make_timeline(tm=3.0, tc=11.5, tq=15.0)  # margin = -0.5
    m_borderline = calculate_mosca_assessment(t_borderline)
    assert m_borderline.margin == -0.5
    assert m_borderline.status == "BORDERLINE"

    # MIGRATION_REQUIRED: margin == 0
    t_req = _make_timeline(tm=3.0, tc=12.0, tq=15.0)  # margin = 0.0
    m_req = calculate_mosca_assessment(t_req)
    assert m_req.margin == 0.0
    assert m_req.status == "MIGRATION_REQUIRED"

    # CRITICAL_URGENCY: margin > 0
    t_crit_small = _make_timeline(tm=3.0, tc=12.1, tq=15.0)  # margin = 0.1
    m_crit_small = calculate_mosca_assessment(t_crit_small)
    assert m_crit_small.margin == pytest.approx(0.1)
    assert m_crit_small.status == "CRITICAL_URGENCY"

    t_crit_large = _make_timeline(tm=4.0, tc=15.0, tq=15.0)  # margin = 4.0
    m_crit_large = calculate_mosca_assessment(t_crit_large)
    assert m_crit_large.margin == 4.0
    assert m_crit_large.status == "CRITICAL_URGENCY"


# =========================================================================
# 5. HNDL scoring across documented timeline values
# =========================================================================

def test_hndl_scoring_across_documented_timeline_values():
    """Verify HNDL exposure scales with data lifetime (Tc) relative to quantum threat horizon (Tq)."""
    # When Tc >= Tq, data outlasts the quantum horizon -> full exposure (lifetime_factor = 1.0)
    t_long = _make_timeline(tm=2.0, tc=20.0, tq=15.0)
    h_long = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=t_long)
    assert h_long.exposure == 100.0
    assert h_long.weight == 1.5

    # Boundary Tc == Tq -> lifetime_factor = 1.0
    t_equal = _make_timeline(tm=2.0, tc=15.0, tq=15.0)
    h_equal = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=t_equal)
    assert h_equal.exposure == 100.0
    assert h_equal.weight == 1.5

    # When 0 < Tc < Tq, exposure scales proportionally by Tc / Tq
    # Tc = 5, Tq = 15 -> lifetime_factor = 5 / 15 = 1/3
    # SENSITIVITY_WEIGHT["CONFIDENTIAL"] = 0.7 -> exposure_ratio = 0.7 * (1/3) = 0.2333 -> exposure = 23.33
    t_prop = _make_timeline(tm=2.0, tc=5.0, tq=15.0)
    h_prop = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="CONFIDENTIAL", timeline=t_prop)
    assert h_prop.exposure == 23.33
    assert h_prop.weight == pytest.approx(1.12, abs=0.01)

    # Short-lived data: Tc = 1, Tq = 15 -> lifetime_factor = 1 / 15
    # SENSITIVITY_WEIGHT["INTERNAL"] = 0.3 -> exposure_ratio = 0.3 * (1/15) = 0.02 -> exposure = 2.0
    t_short = _make_timeline(tm=2.0, tc=1.0, tq=15.0)
    h_short = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="INTERNAL", timeline=t_short)
    assert h_short.exposure == 2.0
    assert h_short.weight == 1.01

    # Zero confidentiality lifetime: Tc = 0.0 -> exposure = 0.0
    t_zero = _make_timeline(tm=2.0, tc=0.0, tq=15.0)
    h_zero = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=t_zero)
    assert h_zero.exposure == 0.0
    assert h_zero.weight == 1.0


# =========================================================================
# 6. HNDL behavior when timeline data is missing or invalid
# =========================================================================

def test_hndl_behavior_when_timeline_data_is_missing_or_invalid():
    """Verify missing/incomplete timeline data preserves uncertainty and does not falsely classify as safe."""
    # 1. timeline is None -> conservative assumption (lifetime_factor = 1.0)
    h_none = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=None)
    assert h_none.exposure == 100.0
    assert h_none.weight == 1.5

    # 2. Tc is None -> conservative assumption
    t_no_tc = QuantumTimeline(
        Tm=TimeValue(value=2.0),
        Tc=TimeValue(value=None),
        Tq=TimeValue(value=15.0),
    )
    h_no_tc = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="CONFIDENTIAL", timeline=t_no_tc)
    assert h_no_tc.exposure == 70.0
    assert h_no_tc.weight == 1.35

    # 3. Tq is None -> conservative assumption
    t_no_tq = QuantumTimeline(
        Tm=TimeValue(value=2.0),
        Tc=TimeValue(value=10.0),
        Tq=TimeValue(value=None),
    )
    h_no_tq = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="CONFIDENTIAL", timeline=t_no_tq)
    assert h_no_tq.exposure == 70.0

    # 4. Tq <= 0 -> immediate quantum horizon -> full exposure if Tc > 0
    t_zero_tq = _make_timeline(tm=2.0, tc=5.0, tq=0.0)
    h_zero_tq = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=t_zero_tq)
    assert h_zero_tq.exposure == 100.0

    # 5. Negative Tc -> data is expired -> exposure 0.0
    t_neg_tc = _make_timeline(tm=2.0, tc=-2.0, tq=15.0)
    h_neg_tc = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=t_neg_tc)
    assert h_neg_tc.exposure == 0.0


# =========================================================================
# 7. Sensitivity-level differences and strict monotonicity
# =========================================================================

def test_hndl_sensitivity_level_differences():
    """Verify exposure strictly respects data sensitivity hierarchy when timeline is fixed."""
    tl = _make_timeline(tm=2.0, tc=20.0, tq=15.0)  # lifetime_factor = 1.0

    scores = {}
    for level in ("PUBLIC", "INTERNAL", "UNKNOWN", "CONFIDENTIAL", "SENSITIVE", "HIGHLY_SENSITIVE", "LONG_TERM_SECRET"):
        h = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity=level, timeline=tl)
        scores[level] = h.exposure

    assert scores["PUBLIC"] == 0.0
    assert scores["PUBLIC"] < scores["INTERNAL"]
    assert scores["INTERNAL"] < scores["UNKNOWN"]
    assert scores["UNKNOWN"] < scores["CONFIDENTIAL"]
    assert scores["CONFIDENTIAL"] < scores["SENSITIVE"]
    assert scores["SENSITIVE"] < scores["HIGHLY_SENSITIVE"]
    assert scores["HIGHLY_SENSITIVE"] == scores["LONG_TERM_SECRET"] == 100.0


# =========================================================================
# 8. Interaction between HNDL results and quantum-risk aggregation
# =========================================================================

def test_hndl_interaction_with_quantum_risk_and_aggregation():
    """Verify HNDL weight amplifies risk in QuantumRiskEngine and reflects correctly in AggregationEngine."""
    # ECDHE (Asymmetric KEX, Shor affected, algorithmic_risk = 75.0)
    # With HIGHLY_SENSITIVE + long Tc (20y vs Tq=15y): HNDL weight = 1.5
    # Overall risk = 75.0 * 1.5 = 112.5 -> capped at 100.0 -> CRITICAL / P0
    tl_high = _make_timeline(tm=2.0, tc=20.0, tq=15.0)
    ass_high = assess_quantum_risk(
        asset_id="ast-hndl-high",
        algorithm_name="ECDHE",
        timeline=tl_high,
        key_exchange_role=True,
        data_sensitivity="HIGHLY_SENSITIVE",
    )
    assert ass_high.hndl.exposure == 100.0
    assert ass_high.hndl.weight == 1.5
    assert ass_high.overall_quantum_risk == 100.0
    assert ass_high.risk_tier == "CRITICAL"
    assert ass_high.migration_priority == "P0"

    # With PUBLIC data (sensitivity 0): HNDL weight = 1.0
    # Overall risk = 75.0 * 1.0 = 75.0 (with Mosca margin = -8 <= -2 -> SAFE_MARGIN) -> HIGH / P1
    tl_pub = _make_timeline(tm=2.0, tc=0.0, tq=15.0)
    ass_pub = assess_quantum_risk(
        asset_id="ast-hndl-pub",
        algorithm_name="ECDHE",
        timeline=tl_pub,
        key_exchange_role=True,
        data_sensitivity="PUBLIC",
    )
    assert ass_pub.hndl.exposure == 0.0
    assert ass_pub.hndl.weight == 1.0
    assert ass_pub.overall_quantum_risk == 75.0
    assert ass_pub.risk_tier == "HIGH"
    assert ass_pub.migration_priority == "P1"

    # Aggregation check
    summary = aggregate_asset_risk("ast-agg", [ass_high, ass_pub])
    assert summary.hndl.exposure == 100.0
    assert summary.hndl.classification == "CRITICAL"
    assert summary.risk_tier == "CRITICAL"


# =========================================================================
# 9. Unknown or insufficient-evidence semantics in Mosca and HNDL
# =========================================================================

def test_unknown_insufficient_evidence_semantics():
    """Verify Mosca and HNDL handle missing/unknown inputs without falsely claiming safety."""
    # Mosca with missing fields
    t_incomplete = QuantumTimeline(
        Tm=TimeValue(value=None),
        Tc=TimeValue(value=5.0),
        Tq=TimeValue(value=15.0),
    )
    m_inc = calculate_mosca_assessment(t_incomplete)
    assert m_inc.margin is None
    assert m_inc.status == "INSUFFICIENT_DATA"

    # Non-KEX algorithm (e.g. ECDSA signature) -> HNDL exposure is strictly 0.0
    tl = _make_timeline()
    h_non_kex = calculate_hndl_exposure(is_vulnerable_kex=False, data_sensitivity="HIGHLY_SENSITIVE", timeline=tl)
    assert h_non_kex.exposure == 0.0
    assert h_non_kex.vulnerable_crypto is False
    assert h_non_kex.key_exchange_exposure is False

    # Unknown algorithm risk assessment
    ass_unknown = assess_quantum_risk(
        asset_id="ast-unk",
        algorithm_name="TOTALLY_UNKNOWN_CIPHER",
        timeline=tl,
    )
    assert ass_unknown.risk_tier == "UNKNOWN"
    assert ass_unknown.migration_priority == "UNKNOWN"
    assert ass_unknown.confidence == 0.2


# =========================================================================
# 10. Backward compatibility with Phase 4.1 and Phase 4.2 assets
# =========================================================================

def test_backward_compatibility_with_phase4_1_and_4_2():
    """Verify full end-to-end resolution and aggregation of Phase 4.1 & 4.2 asset structures."""
    # TLS service asset with compound cipher suite
    svc_asset = CanonicalAsset(
        scan_id="scan-compat-43",
        asset_type=AssetType.SERVICE,
        name="web.pnb.bank:443",
        observed_at=datetime.now(timezone.utc),
        properties={
            "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
            "tlsVersion": "TLSv1.2",
            "data_classification": "CONFIDENTIAL",
        },
    )

    assessments = resolve_asset_quantum_risk(svc_asset)
    assert len(assessments) == 4

    # The ECDHE component has vulnerable KEX and CONFIDENTIAL data
    ecdhe_ass = next(a for a in assessments if a.subject_id == "sub-ecdhe")
    assert ecdhe_ass.hndl.vulnerable_crypto is True
    assert ecdhe_ass.hndl.key_exchange_exposure is True
    assert ecdhe_ass.hndl.exposure > 0.0

    # The RSA authentication component is not KEX in this context -> no HNDL exposure
    rsa_ass = next(a for a in assessments if a.subject_id == "sub-rsa")
    assert rsa_ass.hndl.key_exchange_exposure is False
    assert rsa_ass.hndl.exposure == 0.0

    # Aggregate
    summary = aggregate_asset_risk("ast-svc", assessments)
    assert summary.risk_tier in ("CRITICAL", "HIGH")
    assert summary.hndl.exposure > 0.0
    assert summary.mosca.status == "SAFE_MARGIN"  # default timeline: Tm=2, Tc=5, Tq=15 -> margin = -8 <= -2
