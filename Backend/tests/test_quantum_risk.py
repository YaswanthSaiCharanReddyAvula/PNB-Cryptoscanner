import pytest
from app.scanner.quantum.models import QuantumTimeline, TimeValue
from app.scanner.quantum.mosca_engine import calculate_mosca_assessment
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk
from app.scanner.quantum.hndl_engine import calculate_hndl_exposure


def test_mosca_margin():
    t_timeline = QuantumTimeline(
        Tm=TimeValue(value=3),
        Tc=TimeValue(value=10),
        Tq=TimeValue(value=15)
    )
    mosca = calculate_mosca_assessment(t_timeline)
    assert mosca.margin == -2
    assert mosca.status == "SAFE_MARGIN"

    t_timeline_2 = QuantumTimeline(
        Tm=TimeValue(value=4),
        Tc=TimeValue(value=15),
        Tq=TimeValue(value=15)
    )
    mosca_2 = calculate_mosca_assessment(t_timeline_2)
    assert mosca_2.margin == 4
    assert mosca_2.status == "CRITICAL_URGENCY"


def test_invariant_1_tc_increases():
    # Tc increases -> urgency must not decrease (Mosca margin goes up)
    t1 = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=5), Tq=TimeValue(value=15))
    m1 = calculate_mosca_assessment(t1)

    t2 = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=10), Tq=TimeValue(value=15))
    m2 = calculate_mosca_assessment(t2)

    assert m2.margin > m1.margin

def test_invariant_2_tm_increases():
    # Tm increases -> urgency must not decrease
    t1 = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=5), Tq=TimeValue(value=15))
    m1 = calculate_mosca_assessment(t1)

    t2 = QuantumTimeline(Tm=TimeValue(value=4), Tc=TimeValue(value=5), Tq=TimeValue(value=15))
    m2 = calculate_mosca_assessment(t2)

    assert m2.margin > m1.margin

def test_invariant_3_tq_decreases():
    # Tq decreases -> urgency must not decrease
    t1 = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=5), Tq=TimeValue(value=15))
    m1 = calculate_mosca_assessment(t1)

    t2 = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=5), Tq=TimeValue(value=10))
    m2 = calculate_mosca_assessment(t2)

    assert m2.margin > m1.margin

def test_hndl_test_matrix():
    timeline = QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=20), Tq=TimeValue(value=15))
    
    # ECDHE + public short-lived data
    h1 = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="PUBLIC", timeline=QuantumTimeline(Tm=TimeValue(value=2), Tc=TimeValue(value=1), Tq=TimeValue(value=15)))
    assert h1.exposure == 0.0

    # ECDHE + sensitive long-lived data
    h2 = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="HIGHLY_SENSITIVE", timeline=timeline)
    assert h2.exposure == 100.0

    # RSA key exchange + long-lived data
    h3 = calculate_hndl_exposure(is_vulnerable_kex=True, data_sensitivity="CONFIDENTIAL", timeline=timeline)
    assert h3.exposure > 0.0

    # ECDSA signature + long-lived data (not KEX)
    h4 = calculate_hndl_exposure(is_vulnerable_kex=False, data_sensitivity="HIGHLY_SENSITIVE", timeline=timeline)
    assert h4.exposure == 0.0

def test_missing_data_semantics():
    t_missing = QuantumTimeline(
        Tm=TimeValue(value=None),
        Tc=TimeValue(value=None),
        Tq=TimeValue(value=None)
    )
    mosca = calculate_mosca_assessment(t_missing)
    assert mosca.margin is None
    assert mosca.status == "INSUFFICIENT_DATA"
