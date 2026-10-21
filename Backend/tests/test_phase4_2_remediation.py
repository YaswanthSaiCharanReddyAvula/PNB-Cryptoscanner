"""
QuantumShield — Phase 4.2 Regression Tests
Algorithm Normalization and Unknown-Risk Aggregation

Covers:
1. Case and separator normalization.
2. RSA and AES names with key sizes.
3. Recognized curve aliases, where supported.
4. Compound cipher-suite decomposition.
5. Preservation of the original observed suite as evidence.
6. Unsupported and ambiguous algorithm names.
7. Duplicate primitive suppression.
8. Aggregation of all-known assets.
9. Aggregation of mixed known and unknown assets.
10. Aggregation of all-unknown assets.
11. Empty assessment collection semantics.
12. Backward compatibility with Phase 4.1 TLS-shaped and crypto:-prefixed assets.
"""

import uuid
from datetime import datetime, timezone
import pytest

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalProperty,
    AssetType,
)
from app.scanner.engines.crypto_normalization import CryptoNormalization
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk
from app.scanner.quantum.aggregation_engine import (
    aggregate_asset_risk,
    aggregate_organization_risk,
)
from app.scanner.quantum.models import (
    QuantumRiskAssessment,
    QuantumTimeline,
    TimeValue,
    AssetQuantumRiskSummary,
)


def _make_timeline() -> QuantumTimeline:
    return QuantumTimeline(
        Tm=TimeValue(value=2.0, unit="years", source="default_policy", confidence=0.7, assumption="migration"),
        Tc=TimeValue(value=5.0, unit="years", source="default_policy", confidence=0.8, assumption="collapse"),
        Tq=TimeValue(value=10.0, unit="years", source="scenario_baseline", confidence=0.5, assumption="threat"),
    )


# =========================================================================
# 1. Case and separator normalization
# =========================================================================

def test_case_and_separator_normalization():
    """Verify algorithm names with mixed case, underscores, spaces, or hyphens normalize deterministically."""
    # Test normalization utility directly
    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("rsa_2048")
    assert prim == "RSA"
    assert bits == 2048

    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("aes_256_cbc")
    assert prim == "AES-256"
    assert bits == 256

    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("sha 256")
    assert prim == "SHA-256"
    assert bits == 256

    # Test through quantum risk assessment
    tl = _make_timeline()
    ass = assess_quantum_risk(
        asset_id="ast-1",
        algorithm_name="rsa_2048",
        timeline=tl,
    )
    assert ass.subject_id == "sub-rsa"
    assert ass.risk_tier == "HIGH"
    assert ass.shor_assessment is not None
    assert ass.shor_assessment.key_size == 2048
    assert any("Normalized algorithm" in a for a in ass.assumptions)


# =========================================================================
# 2. RSA and AES names with key sizes
# =========================================================================

def test_rsa_and_aes_names_with_key_sizes():
    """Verify RSA and AES key-size variants are accurately resolved and scored."""
    tl = _make_timeline()

    # RSA-2048
    ass_rsa2048 = assess_quantum_risk(
        asset_id="ast-rsa-2048",
        algorithm_name="RSA-2048",
        timeline=tl,
    )
    assert ass_rsa2048.shor_assessment is not None
    assert ass_rsa2048.shor_assessment.key_size == 2048
    assert ass_rsa2048.risk_tier == "HIGH"
    assert ass_rsa2048.migration_priority == "P1"

    # RSA-1024
    ass_rsa1024 = assess_quantum_risk(
        asset_id="ast-rsa-1024",
        algorithm_name="RSA-1024",
        timeline=tl,
    )
    assert ass_rsa1024.shor_assessment.key_size == 1024
    assert ass_rsa1024.algorithmic_risk == 75.0
    assert ass_rsa1024.risk_tier == "HIGH"

    # AES-128
    ass_aes128 = assess_quantum_risk(
        asset_id="ast-aes-128",
        algorithm_name="AES-128",
        timeline=tl,
    )
    assert ass_aes128.grover_assessment is not None
    assert ass_aes128.grover_assessment.effective_security_bits == 64
    assert ass_aes128.risk_tier == "MEDIUM"

    # AES-256
    ass_aes256 = assess_quantum_risk(
        asset_id="ast-aes-256",
        algorithm_name="AES-256",
        timeline=tl,
    )
    assert ass_aes256.grover_assessment is not None
    assert ass_aes256.grover_assessment.effective_security_bits == 128
    assert ass_aes256.risk_tier == "LOW"


# =========================================================================
# 3. Recognized curve aliases
# =========================================================================

def test_recognized_curve_aliases():
    """Verify common elliptic-curve aliases resolve to recognized canonical primitives."""
    # NIST curves
    for alias in ("secp256r1", "prime256v1", "P-256", "nistp256"):
        prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive(alias, default_kex=True)
        assert prim == "ECDH"
        assert bits == 256
        assert curve == "secp256r1"
        assert is_kex is True

    # P-384
    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("P-384", default_kex=False)
    assert prim == "ECDSA"
    assert bits == 384
    assert curve == "secp384r1"

    # X25519 & Ed25519
    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("X25519")
    assert prim == "X25519"
    assert bits == 256
    assert is_kex is True
    assert curve == "curve25519"

    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("curve25519")
    assert prim == "X25519"
    assert is_kex is True

    prim, bits, is_kex, curve = CryptoNormalization.resolve_primitive("ed25519")
    assert prim == "ED25519"
    assert is_kex is False


# =========================================================================
# 4. Compound cipher-suite decomposition
# =========================================================================

def test_compound_cipher_suite_decomposition():
    """Verify compound TLS cipher-suites are decomposed into constituent primitives without fabricating components."""
    # 1. TLS 1.2 compound suite
    decomposed_12 = CryptoNormalization.decompose_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")
    roles = {c["role"]: c for c in decomposed_12}
    assert "key_exchange" in roles
    assert roles["key_exchange"]["primitive"] == "ECDHE"
    assert roles["key_exchange"]["is_kex"] is True

    assert "authentication" in roles
    assert roles["authentication"]["primitive"] == "RSA"

    assert "encryption" in roles
    assert roles["encryption"]["primitive"] == "AES-128"

    assert "hash" in roles
    assert roles["hash"]["primitive"] == "SHA-256"

    # 2. TLS 1.3 suite (MUST NOT invent key_exchange or authentication)
    decomposed_13 = CryptoNormalization.decompose_cipher_suite("TLS_AES_256_GCM_SHA384")
    roles_13 = {c["role"]: c for c in decomposed_13}
    assert "encryption" in roles_13
    assert roles_13["encryption"]["primitive"] == "AES-256"
    assert "hash" in roles_13
    assert roles_13["hash"]["primitive"] == "SHA-384"
    assert "key_exchange" not in roles_13
    assert "authentication" not in roles_13


# =========================================================================
# 5. Preservation of the original observed suite as evidence
# =========================================================================

def test_preservation_of_original_suite_as_evidence():
    """Verify decomposed assessments preserve the original suite name, role, and protocol context in evidence."""
    asset = CanonicalAsset(
        scan_id="scan-tls-ev",
        asset_type=AssetType.SERVICE,
        name="gateway.pnb.bank:443",
        observed_at=datetime.now(timezone.utc),
        properties={
            "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
            "tlsVersion": "TLSv1.2",
        },
    )

    assessments = resolve_asset_quantum_risk(asset)
    assert len(assessments) == 4

    for ass in assessments:
        # Must preserve original suite name
        assert any("ECDHE-RSA-AES128-GCM-SHA256" in ev for ev in ass.evidence)
        # Must preserve canonical property origin
        assert any("cipherSuite" in ev for ev in ass.evidence)
        # Must preserve protocol context
        assert any("tlsVersion=TLSv1.2" in ev for ev in ass.evidence)


# =========================================================================
# 6. Unsupported and ambiguous algorithm names
# =========================================================================

def test_unsupported_and_ambiguous_algorithm_names():
    """Verify unrecognized or unsupported algorithms remain explicitly UNKNOWN with visible uncertainty."""
    tl = _make_timeline()
    ass = assess_quantum_risk(
        asset_id="ast-unsupported",
        algorithm_name="MY_CUSTOM_CIPHER_V3",
        timeline=tl,
    )

    assert ass.risk_tier == "UNKNOWN"
    assert ass.migration_priority == "UNKNOWN"
    assert ass.confidence == 0.2
    assert ass.shor_assessment is None
    assert ass.grover_assessment is None
    assert any("Algorithm MY_CUSTOM_CIPHER_V3 unknown, assuming INSUFFICIENT_DATA" in a for a in ass.assumptions)


# =========================================================================
# 7. Duplicate primitive suppression
# =========================================================================

def test_duplicate_primitive_suppression():
    """Verify redundant declarations of the same primitive on an asset do not generate duplicate assessments."""
    asset = CanonicalAsset(
        scan_id="scan-dedup",
        asset_type=AssetType.CERTIFICATE,
        name="cert.pnb.bank",
        observed_at=datetime.now(timezone.utc),
        properties={
            "keyType": "RSA",
            "keySize": 2048,
            "crypto:tls:auth": "RSA-2048",
            "algorithm": "RSA",
        },
    )

    assessments = resolve_asset_quantum_risk(asset)
    rsa_assessments = [a for a in assessments if a.subject_id == "sub-rsa"]
    assert len(rsa_assessments) == 1
    assert rsa_assessments[0].shor_assessment.key_size == 2048


# =========================================================================
# 8. Aggregation of all-known assets
# =========================================================================

def test_aggregation_all_known_assets():
    """Verify aggregate risk calculations for a collection containing only known algorithms."""
    tl = _make_timeline()
    ass_aes = assess_quantum_risk("a1", "AES-256", tl)
    ass_pqc = assess_quantum_risk("a2", "ML-KEM", tl)

    # Asset-level aggregation
    asset_summary = aggregate_asset_risk("ast-known", [ass_aes, ass_pqc])
    assert len(asset_summary.assessments) == 2
    assert asset_summary.unknown_coverage == 0.0
    # Between LOW (AES-256) and SAFE (ML-KEM), worst is LOW
    assert asset_summary.risk_tier == "LOW"
    assert asset_summary.migration_priority == "P3"

    # Org-level aggregation
    org_summary = aggregate_organization_risk([asset_summary])
    assert org_summary.total_assets == 1
    assert org_summary.risk_tier == "LOW"
    assert org_summary.unknown_crypto_assets == 0
    assert org_summary.known_coverage == 1.0
    assert org_summary.unknown_coverage == 0.0


# =========================================================================
# 9. Aggregation of mixed known and unknown assets
# =========================================================================

def test_aggregation_mixed_known_and_unknown_assets():
    """Verify unknown assets are tracked, not masked as SAFE, and visible in coverage."""
    tl = _make_timeline()
    ass_safe = assess_quantum_risk("a1", "ML-KEM", tl)  # SAFE
    ass_unknown = assess_quantum_risk("a2", "UNKNOWN_ALGO_XYZ", tl)  # UNKNOWN

    # Asset-level aggregation
    asset_summary = aggregate_asset_risk("ast-mixed", [ass_safe, ass_unknown])
    assert asset_summary.unknown_coverage == 0.5
    # UNKNOWN must take precedence over SAFE: worst_tier must NOT be SAFE!
    assert asset_summary.risk_tier == "UNKNOWN"
    assert asset_summary.migration_priority == "UNKNOWN"

    # Org-level aggregation
    org_summary = aggregate_organization_risk([asset_summary])
    assert org_summary.risk_tier == "UNKNOWN"
    assert org_summary.unknown_crypto_assets == 1
    assert org_summary.unknown_coverage == 0.5
    assert org_summary.known_coverage == 0.5


# =========================================================================
# 10. Aggregation of all-unknown assets
# =========================================================================

def test_aggregation_all_unknown_assets():
    """Verify a collection of only unknown assets aggregates to UNKNOWN without crashing or fabricating SAFE."""
    tl = _make_timeline()
    ass_u1 = assess_quantum_risk("a1", "UNKNOWN_1", tl)
    ass_u2 = assess_quantum_risk("a2", "UNKNOWN_2", tl)

    asset_summary = aggregate_asset_risk("ast-unknown", [ass_u1, ass_u2])
    assert asset_summary.unknown_coverage == 1.0
    assert asset_summary.risk_tier == "UNKNOWN"
    assert asset_summary.migration_priority == "UNKNOWN"
    assert asset_summary.quantum_risk_score == 0.0

    org_summary = aggregate_organization_risk([asset_summary])
    assert org_summary.risk_tier == "UNKNOWN"
    assert org_summary.total_assets == 1
    assert org_summary.unknown_crypto_assets == 1
    assert org_summary.known_coverage == 0.0
    assert org_summary.unknown_coverage == 1.0


# =========================================================================
# 11. Empty assessment collection semantics
# =========================================================================

def test_empty_assessment_collection_semantics():
    """Verify empty inventory returns explicit UNKNOWN semantics and zeroed counts, not fabricated SAFE."""
    # Asset-level empty
    asset_summary = aggregate_asset_risk("ast-empty", [])
    assert asset_summary.risk_tier == "UNKNOWN"
    assert asset_summary.migration_priority == "UNKNOWN"
    assert asset_summary.mosca.status == "NOT_APPLICABLE"
    assert asset_summary.hndl.classification == "UNKNOWN"
    assert asset_summary.unknown_coverage == 1.0
    assert asset_summary.quantum_risk_score == 0.0
    assert asset_summary.confidence == 0.0
    assert len(asset_summary.assessments) == 0

    # Org-level empty
    org_summary = aggregate_organization_risk([])
    assert org_summary.total_assets == 0
    assert org_summary.critical_assets == 0
    assert org_summary.p0_assets == 0
    assert org_summary.risk_tier == "UNKNOWN"
    assert org_summary.known_coverage == 0.0
    assert org_summary.unknown_coverage == 1.0
    assert org_summary.overall_quantum_risk_score == 0.0
    assert org_summary.confidence == 0.0


# =========================================================================
# 12. Backward compatibility with Phase 4.1 TLS-shaped and crypto: assets
# =========================================================================

def test_backward_compatibility_phase4_1_and_prefixed():
    """Verify backward compatibility with Phase 4.1 canonical and legacy prefixed assets."""
    # Legacy prefixed asset
    legacy_asset = CanonicalAsset(
        scan_id="scan-legacy",
        asset_type=AssetType.SERVICE,
        name="legacy-gateway",
        observed_at=datetime.now(timezone.utc),
        properties={
            "crypto:tls:kex": "ECDHE",
            "crypto:tls:enc": "AES-128",
        },
    )
    legacy_ass = resolve_asset_quantum_risk(legacy_asset)
    assert len(legacy_ass) == 2
    sub_ids = {a.subject_id for a in legacy_ass}
    assert "sub-ecdhe" in sub_ids
    assert "sub-aes-128" in sub_ids

    # Phase 4.1 certificate asset
    cert_asset = CanonicalAsset(
        scan_id="scan-cert",
        asset_type=AssetType.CERTIFICATE,
        name="web-cert",
        observed_at=datetime.now(timezone.utc),
        properties={
            "keyType": "RSA",
            "keySize": 2048,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        },
    )
    cert_ass = resolve_asset_quantum_risk(cert_asset)
    assert len(cert_ass) == 2
    cert_subs = {a.subject_id: a for a in cert_ass}
    assert "sub-rsa" in cert_subs
    assert cert_subs["sub-rsa"].risk_tier == "HIGH"
    assert "sub-sha256withrsaencryption" in cert_subs
    assert cert_subs["sub-sha256withrsaencryption"].risk_tier == "UNKNOWN"
