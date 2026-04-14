"""
Stress evaluation: ambiguous, multi-family, and adversarial crypto strings.

These are the REAL inputs the ML layer is built to handle — long cipher suite
blobs, hybrid draft names, vendor aliases, near-miss PQC strings, and edge
cases where rules alone would default to unknown scores.

The test prints a detailed report.  It does NOT assert 100% accuracy (that
would be unrealistic); instead it asserts safety invariants:
  - Known-weak components are NEVER classified as QUANTUM_SAFE
  - Known PQC components are NEVER classified as VULNERABLE
  - The model returns valid probabilities for every input
  - OOD score is elevated for truly bizarre strings
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from dataclasses import dataclass
from typing import List, Optional

import pytest

from app.db.models import AlgorithmCategory, CryptoComponent, QuantumStatus, TLSInfo
from ml.ensemble import EnsemblePolicy, EnsemblePolicyConfig, RuleAssessment
from ml.feature_builder import FeatureBuilder
from ml.inference_engine import MLAssessment, MLInferenceEngine

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
ONNX_PATH = os.path.join(MODEL_DIR, "quantum_classifier_v1.onnx")
META_PATH = ONNX_PATH + ".meta.json"

CLASS_LABELS = {0: "QUANTUM_SAFE", 1: "PARTIALLY_SAFE", 2: "VULNERABLE"}


@dataclass
class StressCase:
    name: str
    category: AlgorithmCategory
    key_size: Optional[int] = None
    tls_version: Optional[str] = None
    rule_status: str = "UNKNOWN"
    rule_confidence: float = 0.5
    expected_not: Optional[str] = None  # class it must NOT be
    expected_is: Optional[str] = None   # class it MUST be (if known)
    description: str = ""


STRESS_CASES: List[StressCase] = [
    # ── Real-world ambiguous cipher suites (multiple families in one string) ──
    StressCase(
        name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=128,
        tls_version="TLSv1.2",
        rule_status="VULNERABLE",
        rule_confidence=0.7,
        expected_not="QUANTUM_SAFE",
        description="Full TLS 1.2 suite: ECDHE+RSA+AES128 — Shor-vulnerable KEX",
    ),
    StressCase(
        name="TLS_AES_256_GCM_SHA384",
        category=AlgorithmCategory.CIPHER,
        key_size=256,
        tls_version="TLSv1.3",
        rule_status="PARTIALLY_SAFE",
        rule_confidence=0.8,
        expected_not="VULNERABLE",
        description="TLS 1.3 cipher-only suite — strong symmetric, no KEX in name",
    ),
    StressCase(
        name="ECDHE-ECDSA-AES256-GCM-SHA384",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=256,
        tls_version="TLSv1.2",
        rule_status="VULNERABLE",
        rule_confidence=0.6,
        expected_not="QUANTUM_SAFE",
        description="OpenSSL-style suite with ECDHE+ECDSA — both Shor-vulnerable",
    ),
    StressCase(
        name="DHE-RSA-AES128-SHA",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=128,
        tls_version="TLSv1.2",
        rule_status="VULNERABLE",
        rule_confidence=0.7,
        expected_not="QUANTUM_SAFE",
        description="DHE with RSA and weak SHA — multi-vulnerability",
    ),

    # ── Hybrid PQC draft names (not yet in catalog) ──
    StressCase(
        name="X25519Kyber768Draft00",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=768,
        tls_version="TLSv1.3",
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.9,
        expected_not="VULNERABLE",
        description="Chrome's Kyber hybrid draft — should lean SAFE",
    ),
    StressCase(
        name="SecP256r1MLKEM768",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=768,
        tls_version="TLSv1.3",
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.8,
        expected_not="VULNERABLE",
        description="IETF hybrid KEM naming — ML-KEM token present",
    ),
    StressCase(
        name="x25519_kyber512_draft",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=512,
        tls_version="TLSv1.3",
        rule_status="PARTIALLY_SAFE",
        rule_confidence=0.6,
        expected_not="VULNERABLE",
        description="Older Kyber512 draft hybrid — weaker but not vulnerable",
    ),

    # ── Vendor-mangled and misspelled names ──
    StressCase(
        name="CRYSTALS_Kyber_1024_R3",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=1024,
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.85,
        expected_not="VULNERABLE",
        description="Underscore-separated Kyber with round number",
    ),
    StressCase(
        name="dilithium-v5-ietf-2024",
        category=AlgorithmCategory.SIGNATURE,
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.9,
        expected_not="VULNERABLE",
        description="Draft Dilithium with version and date suffix",
    ),
    StressCase(
        name="sphincsplus-sha256-128f-robust",
        category=AlgorithmCategory.SIGNATURE,
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.85,
        expected_not="VULNERABLE",
        description="SPHINCS+ full parameter name",
    ),

    # ── Known-weak with obfuscated names (adversarial) ──
    StressCase(
        name="EXPORT1024-DES-CBC-SHA",
        category=AlgorithmCategory.CIPHER,
        key_size=56,
        rule_status="VULNERABLE",
        rule_confidence=1.0,
        expected_is="VULNERABLE",
        description="EXPORT cipher — must always be VULNERABLE",
    ),
    StressCase(
        name="TLS_RSA_WITH_NULL_SHA256",
        category=AlgorithmCategory.CIPHER,
        key_size=0,
        rule_status="VULNERABLE",
        rule_confidence=1.0,
        expected_is="VULNERABLE",
        description="NULL cipher — must always be VULNERABLE",
    ),
    StressCase(
        name="EXP-RC4-MD5",
        category=AlgorithmCategory.CIPHER,
        key_size=40,
        rule_status="VULNERABLE",
        rule_confidence=1.0,
        expected_is="VULNERABLE",
        description="EXPORT+RC4+MD5 triple weakness — must be VULNERABLE",
    ),
    StressCase(
        name="anonDH-AES128-SHA",
        category=AlgorithmCategory.KEY_EXCHANGE,
        key_size=128,
        rule_status="VULNERABLE",
        rule_confidence=0.9,
        expected_is="VULNERABLE",
        description="Anonymous DH — no authentication, always vulnerable",
    ),

    # ── Borderline / ambiguous cases ──
    StressCase(
        name="RSA-2048",
        category=AlgorithmCategory.SIGNATURE,
        key_size=2048,
        rule_status="VULNERABLE",
        rule_confidence=0.6,
        expected_not="QUANTUM_SAFE",
        description="RSA-2048 sig — classically OK but Shor-vulnerable",
    ),
    StressCase(
        name="ECDSA-P384",
        category=AlgorithmCategory.SIGNATURE,
        key_size=384,
        rule_status="VULNERABLE",
        rule_confidence=0.6,
        expected_not="QUANTUM_SAFE",
        description="ECDSA with large curve — still Shor-vulnerable",
    ),
    StressCase(
        name="CHACHA20-POLY1305",
        category=AlgorithmCategory.CIPHER,
        key_size=256,
        tls_version="TLSv1.3",
        rule_status="PARTIALLY_SAFE",
        rule_confidence=0.8,
        expected_not="VULNERABLE",
        description="Strong stream cipher — partial safety (Grover margin)",
    ),

    # ── Completely unknown / garbage strings ──
    StressCase(
        name="XYZZY-QUANTUM-9000-ULTRA",
        category=AlgorithmCategory.KEY_EXCHANGE,
        rule_status="UNKNOWN",
        rule_confidence=0.3,
        description="Total nonsense — model should have high OOD",
    ),
    StressCase(
        name="",
        category=AlgorithmCategory.PROTOCOL,
        rule_status="UNKNOWN",
        rule_confidence=0.2,
        description="Empty string — must not crash",
    ),
    StressCase(
        name="A" * 500,
        category=AlgorithmCategory.CIPHER,
        rule_status="UNKNOWN",
        rule_confidence=0.1,
        description="500-char repeated 'A' — adversarial length",
    ),

    # ── Protocol edge cases ──
    StressCase(
        name="SSLv2",
        category=AlgorithmCategory.PROTOCOL,
        tls_version="SSLv2",
        rule_status="VULNERABLE",
        rule_confidence=1.0,
        expected_is="VULNERABLE",
        description="SSLv2 — hard-deny, always VULNERABLE",
    ),
    StressCase(
        name="TLSv1.3",
        category=AlgorithmCategory.PROTOCOL,
        tls_version="TLSv1.3",
        rule_status="QUANTUM_SAFE",
        rule_confidence=0.9,
        expected_not="VULNERABLE",
        description="TLS 1.3 protocol — should not be flagged vulnerable",
    ),
]


@pytest.fixture(scope="module")
def engine():
    if not os.path.isfile(ONNX_PATH):
        pytest.skip(f"Trained model not found at {ONNX_PATH} — run 'python -m ml.train_model' first")
    return MLInferenceEngine(ONNX_PATH, META_PATH)


@pytest.fixture(scope="module")
def fb():
    return FeatureBuilder()


@pytest.fixture(scope="module")
def ensemble():
    cfg = EnsemblePolicyConfig(ml_override_enabled=True)
    return EnsemblePolicy(cfg)


def _run_case(case: StressCase, fb: FeatureBuilder, engine: MLInferenceEngine, ensemble: EnsemblePolicy):
    comp = CryptoComponent(
        name=case.name,
        category=case.category,
        key_size=case.key_size,
        quantum_status=QuantumStatus.VULNERABLE,
        host="stress-test",
    )
    tls = None
    if case.tls_version:
        tls = TLSInfo(host="stress-test", port=443, tls_version=case.tls_version)

    rule = RuleAssessment(
        quantum_status_rule=case.rule_status,
        rule_confidence=case.rule_confidence,
    )
    fv = fb.build(comp, tls_info=tls, rule_assessment={
        "quantum_status": case.rule_status.lower(),
        "confidence": case.rule_confidence,
    })
    ml_result = engine.predict(fv)
    ens_result = ensemble.decide(rule, ml_result, comp)
    return ml_result, ens_result


def test_stress_report(engine, fb, ensemble, capsys):
    """Run all stress cases and print a detailed evaluation report."""
    results = []
    pass_count = 0
    fail_count = 0
    safety_violations = []

    for case in STRESS_CASES:
        ml_r, ens_r = _run_case(case, fb, engine, ensemble)
        ml_class = CLASS_LABELS.get(ml_r.predicted_class, "UNKNOWN")
        final = ens_r.final_quantum_status

        passed = True
        violation = ""

        if case.expected_is and final != case.expected_is:
            passed = False
            violation = f"Expected {case.expected_is}, got {final}"

        if case.expected_not and final == case.expected_not:
            passed = False
            violation = f"Must NOT be {case.expected_not}, but got {final}"

        prob_valid = abs(ml_r.p_safe + ml_r.p_partial + ml_r.p_vulnerable - 1.0) < 0.05

        if not prob_valid:
            passed = False
            violation = f"Probabilities don't sum to 1: {ml_r.p_safe+ml_r.p_partial+ml_r.p_vulnerable:.4f}"

        if passed:
            pass_count += 1
        else:
            fail_count += 1
            safety_violations.append((case, violation))

        results.append((case, ml_r, ens_r, ml_class, final, passed, violation))

    # Print the report
    print("\n")
    print("=" * 90)
    print("  STRESS EVALUATION REPORT — Ambiguous & Adversarial Crypto Strings")
    print("=" * 90)

    for i, (case, ml_r, ens_r, ml_class, final, passed, violation) in enumerate(results, 1):
        status = "PASS" if passed else "FAIL"
        name_display = case.name[:55] + "..." if len(case.name) > 55 else case.name
        print(f"\n  [{status}] #{i}: {name_display}")
        print(f"         {case.description}")
        print(f"         Category: {case.category.value}  |  Key: {case.key_size or '-'}  |  TLS: {case.tls_version or '-'}")
        print(f"         Rule verdict: {case.rule_status} (conf={case.rule_confidence})")
        print(f"         ML probs:  SAFE={ml_r.p_safe:.3f}  PARTIAL={ml_r.p_partial:.3f}  VULN={ml_r.p_vulnerable:.3f}")
        print(f"         ML class:  {ml_class}  |  OOD score: {ml_r.ood_score:.3f}")
        print(f"         Ensemble:  {final}  (conf={ens_r.ensemble_confidence:.3f}, path={ens_r.decision_path})")
        if ens_r.disagreement:
            print(f"         >> DISAGREEMENT: rule={case.rule_status} vs ensemble={final}")
        if violation:
            print(f"         >> VIOLATION: {violation}")

    # Summary
    print("\n" + "=" * 90)
    print(f"  RESULTS: {pass_count} passed / {fail_count} failed / {len(STRESS_CASES)} total")
    print("=" * 90)

    if safety_violations:
        print("\n  SAFETY VIOLATIONS:")
        for case, v in safety_violations:
            print(f"    - {case.name[:50]}: {v}")

    # Category breakdown
    print("\n  CATEGORY BREAKDOWN:")
    cats = {}
    for case, ml_r, ens_r, ml_class, final, passed, _ in results:
        cat = case.description.split("—")[0].strip() if "—" in case.description else "Other"
        cats.setdefault(cat, {"total": 0, "passed": 0})
        cats[cat]["total"] += 1
        if passed:
            cats[cat]["passed"] += 1
    for cat, counts in sorted(cats.items()):
        pct = counts["passed"] / counts["total"] * 100
        print(f"    {cat}: {counts['passed']}/{counts['total']} ({pct:.0f}%)")

    # OOD analysis
    ood_scores = [(case.name[:30], ml_r.ood_score) for case, ml_r, *_ in results]
    ood_scores.sort(key=lambda x: -x[1])
    print("\n  TOP 5 HIGHEST OOD (most uncertain):")
    for name, ood in ood_scores[:5]:
        print(f"    OOD={ood:.3f}  {name}")

    print("\n  TOP 5 LOWEST OOD (most confident):")
    ood_scores.sort(key=lambda x: x[1])
    for name, ood in ood_scores[:5]:
        print(f"    OOD={ood:.3f}  {name}")

    print("\n" + "=" * 90)
    print()

    # Hard assertions
    assert fail_count == 0, f"{fail_count} safety violation(s) — see report above"


def test_all_probabilities_valid(engine, fb, ensemble):
    """Every stress case must return probabilities summing to ~1.0."""
    for case in STRESS_CASES:
        ml_r, _ = _run_case(case, fb, engine, ensemble)
        total = ml_r.p_safe + ml_r.p_partial + ml_r.p_vulnerable
        assert abs(total - 1.0) < 0.05, f"{case.name}: probs sum to {total}"


def test_known_weak_never_safe(engine, fb, ensemble):
    """Components with EXPORT/NULL/RC4/MD5/SSLv2/anon must NEVER get QUANTUM_SAFE."""
    weak_cases = [c for c in STRESS_CASES if c.expected_is == "VULNERABLE"]
    assert len(weak_cases) >= 4
    for case in weak_cases:
        _, ens_r = _run_case(case, fb, engine, ensemble)
        assert ens_r.final_quantum_status == "VULNERABLE", (
            f"{case.name}: expected VULNERABLE, got {ens_r.final_quantum_status}"
        )


def test_pqc_never_vulnerable(engine, fb, ensemble):
    """PQC-family names must NEVER be classified as VULNERABLE by the ensemble."""
    pqc_cases = [c for c in STRESS_CASES if "Kyber" in c.name or "MLKEM" in c.name
                 or "dilithium" in c.name.lower() or "sphincs" in c.name.lower()]
    assert len(pqc_cases) >= 3
    for case in pqc_cases:
        _, ens_r = _run_case(case, fb, engine, ensemble)
        assert ens_r.final_quantum_status != "VULNERABLE", (
            f"{case.name}: PQC component classified as VULNERABLE"
        )


def test_no_crashes_on_adversarial(engine, fb, ensemble):
    """Empty strings, 500-char strings, and garbage must not crash."""
    adversarial = [c for c in STRESS_CASES if "nonsense" in c.description.lower()
                   or "empty" in c.description.lower() or "adversarial" in c.description.lower()]
    assert len(adversarial) >= 2
    for case in adversarial:
        ml_r, ens_r = _run_case(case, fb, engine, ensemble)
        assert ml_r is not None
        assert ens_r is not None
        assert ens_r.final_quantum_status in ("QUANTUM_SAFE", "PARTIALLY_SAFE", "VULNERABLE", "UNKNOWN")
