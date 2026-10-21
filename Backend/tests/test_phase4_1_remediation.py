"""
QuantumShield — Phase 4.1 Regression Tests

Verifies:
1. Canonical property matching in ContextResolver (keyType, keySize, signatureAlgorithm, cipherSuite, algorithm).
2. Backward-compatible support for 'crypto:' prefixed properties.
3. Protocol context (tlsVersion) handling without misclassifying it as an algorithm.
4. Filtering out non-cryptographic properties.
5. Unknown algorithm safety (no schema ValidationError, consistent UNKNOWN migration_priority & risk_tier).
6. Mixed known and unknown algorithms in the same scan.
7. Deduplication of assessments for the same asset and primitive.
8. Error propagation and partial status in QuantumRiskStage.
9. Empty cryptographic inventory handling (does not falsely report SAFE).
"""

import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import MagicMock

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalProperty,
)
from app.scanner.convergence.aggregation import CanonicalInventory
from app.scanner.convergence.enums import AssetType
from app.scanner.pipeline import ScanContext
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk
from app.scanner.quantum.engine_stage import QuantumRiskStage
from app.scanner.quantum.models import (
    QuantumTimeline,
    TimeValue,
    QuantumRiskAssessment,
)
from app.scanner.quantum.aggregation_engine import aggregate_asset_risk


def _default_timeline() -> QuantumTimeline:
    return QuantumTimeline(
        Tm=TimeValue(value=2.0),
        Tc=TimeValue(value=5.0),
        Tq=TimeValue(value=15.0),
    )


# ---------------------------------------------------------------------------
# Task 1 & 2: ContextResolver Property Matching & Asset Handling
# ---------------------------------------------------------------------------

def test_context_resolver_tls_certificate_asset():
    """Verify ContextResolver extracts keyType and signatureAlgorithm from TLSAdapter-shaped cert assets."""
    scan_id = str(uuid.uuid4())
    asset_id = str(uuid.uuid4())
    cert_asset = CanonicalAsset(
        asset_id=asset_id,
        scan_id=scan_id,
        asset_type=AssetType.CERTIFICATE,
        name="CN=pnb.bank",
        observed_at=datetime.now(timezone.utc),
        sources=["tls_engine"],
        evidence_refs=["ev-cert-123"],
        properties={
            "subjectName": "CN=pnb.bank",
            "issuerName": "CN=PNB Internal CA",
            "notValidBefore": "2026-01-01T00:00:00Z",
            "notValidAfter": "2027-01-01T00:00:00Z",
            "signatureAlgorithm": "sha256WithRSAEncryption",
            "signatureAlgorithmOid": "1.2.840.113549.1.1.11",
            "keyType": "RSA",
            "keySize": 2048,
            "daysUntilExpiry": 90,
        },
    )

    assessments = resolve_asset_quantum_risk(cert_asset)

    # Exactly 2 cryptographic subjects: RSA (keyType) and sha256WithRSAEncryption (signatureAlgorithm)
    # Non-cryptographic fields (subjectName, issuerName, dates, OID, daysUntilExpiry) MUST NOT be assessed.
    assert len(assessments) == 2

    alg_names = {a.subject_id: a for a in assessments}
    assert "sub-rsa" in alg_names
    assert "sub-sha256withrsaencryption" in alg_names

    rsa_ass = alg_names["sub-rsa"]
    assert rsa_ass.asset_id == asset_id
    assert rsa_ass.scan_id == scan_id
    assert rsa_ass.shor_assessment is not None
    assert rsa_ass.shor_assessment.key_size == 2048
    assert any("keyType" in ev for ev in rsa_ass.evidence)
    assert any("ev-cert-123" in ev for ev in rsa_ass.evidence)
    assert any("tls_engine" in ev for ev in rsa_ass.evidence)

    sig_ass = alg_names["sub-sha256withrsaencryption"]
    assert sig_ass.asset_id == asset_id
    assert sig_ass.scan_id == scan_id
    assert any("signatureAlgorithm" in ev for ev in sig_ass.evidence)


def test_context_resolver_tls_algorithm_asset():
    """Verify ContextResolver handles AssetType.ALGORITHM assets produced by TLSAdapter for accepted ciphers."""
    scan_id = str(uuid.uuid4())
    asset_id = str(uuid.uuid4())
    algo_asset = CanonicalAsset(
        asset_id=asset_id,
        scan_id=scan_id,
        asset_type=AssetType.ALGORITHM,
        name="TLS_AES_256_GCM_SHA384",
        observed_at=datetime.now(timezone.utc),
        sources=["tls_engine"],
        evidence_refs=["ev-algo-456"],
        properties={
            "primitive": "cipher",
            "mode": "GCM",
            "crypto_functions": ["encryption"],
            "classical_security_level": 256,
            "oid": "2.16.840.1.101.3.4.1.45",
        },
    )

    assessments = resolve_asset_quantum_risk(algo_asset)
    assert len(assessments) >= 1
    subjects = {a.subject_id: a for a in assessments}
    assert "sub-aes-256" in subjects
    ass = subjects["sub-aes-256"]
    assert ass.asset_id == asset_id
    assert ass.scan_id == scan_id
    assert any("ev-algo-456" in ev for ev in ass.evidence)


def test_context_resolver_cipher_suite_and_tls_version():
    """Verify cipherSuite property is resolved and tlsVersion is captured in evidence without generating a fake algorithm."""
    scan_id = str(uuid.uuid4())
    svc_asset = CanonicalAsset(
        scan_id=scan_id,
        asset_type=AssetType.SERVICE,
        name="TLS Service pnb.bank:443",
        observed_at=datetime.now(timezone.utc),
        properties={
            "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
            "tlsVersion": "TLSv1.3",
        },
    )

    assessments = resolve_asset_quantum_risk(svc_asset)
    assert len(assessments) >= 1
    subjects = {a.subject_id: a for a in assessments}
    assert "sub-ecdhe" in subjects
    ass = subjects["sub-ecdhe"]
    # Protocol context must be recorded in evidence
    assert any("TLSv1.3" in ev for ev in ass.evidence)


def test_context_resolver_prefixed_crypto_properties_backward_compat():
    """Verify existing 'crypto:*' prefixed properties continue to be resolved."""
    asset = CanonicalAsset(
        scan_id="scan-legacy",
        asset_type=AssetType.SERVICE,
        name="legacy-gateway",
        observed_at=datetime.now(timezone.utc),
        properties={
            "crypto:tls:kex": "ECDHE",
            "crypto:tls:enc": "AES-128",
        },
    )

    assessments = resolve_asset_quantum_risk(asset)
    assert len(assessments) == 2
    subjects = {a.subject_id for a in assessments}
    assert "sub-ecdhe" in subjects
    assert "sub-aes-128" in subjects


def test_context_resolver_non_crypto_asset_returns_empty():
    """Verify an asset with no eligible cryptographic properties returns an empty assessment list."""
    host_asset = CanonicalAsset(
        scan_id="scan-host",
        asset_type=AssetType.HOST,
        name="192.168.1.50",
        observed_at=datetime.now(timezone.utc),
        properties={
            "ip": "192.168.1.50",
            "hostname": "db01.internal",
            "os": "Ubuntu 22.04",
        },
    )

    assessments = resolve_asset_quantum_risk(host_asset)
    assert assessments == []

    # Aggregated asset summary must reflect unassessed/unknown state
    summary = aggregate_asset_risk(host_asset.asset_id, assessments)
    assert summary.quantum_risk_score == 0.0
    assert summary.risk_tier == "UNKNOWN"
    assert summary.migration_priority == "UNKNOWN"
    assert summary.unknown_coverage == 1.0
    assert summary.confidence == 0.0


def test_context_resolver_deduplication():
    """Verify duplicate definitions of the same primitive on the same asset produce only one assessment."""
    asset = CanonicalAsset(
        scan_id="scan-dedup",
        asset_type=AssetType.CERTIFICATE,
        name="cert-dup",
        observed_at=datetime.now(timezone.utc),
        properties={
            "keyType": "RSA",
            "keySize": 2048,
            "crypto:tls:sig": "RSA",  # Duplicate mention of RSA
        },
    )

    assessments = resolve_asset_quantum_risk(asset)
    # Must only generate 1 assessment for RSA
    assert len(assessments) == 1
    assert assessments[0].subject_id == "sub-rsa"


# ---------------------------------------------------------------------------
# Task 2: Unknown-Algorithm Schema Handling
# ---------------------------------------------------------------------------

def test_unknown_algorithm_no_validation_error():
    """Verify an unrecognized algorithm does not crash with a Pydantic ValidationError."""
    timeline = _default_timeline()

    # Algorithm not in QUANTUM_ALGORITHM_TAXONOMY
    assessment = assess_quantum_risk(
        asset_id="asset-test-unk",
        algorithm_name="CUSTOM-EXPERIMENTAL-PQC-99",
        timeline=timeline,
        scan_id="scan-unk-1",
    )

    assert isinstance(assessment, QuantumRiskAssessment)
    assert assessment.scan_id == "scan-unk-1"
    assert assessment.risk_tier == "UNKNOWN"
    assert assessment.migration_priority == "UNKNOWN"
    assert assessment.confidence == 0.2
    assert assessment.overall_quantum_risk == 0.0
    assert any("INSUFFICIENT_DATA" in asm for asm in assessment.assumptions)


def test_mixed_known_and_unknown_algorithms():
    """Verify a scan with both known and unknown algorithms processes all without aborting."""
    asset = CanonicalAsset(
        scan_id="scan-mixed",
        asset_type=AssetType.CERTIFICATE,
        name="mixed-cert",
        observed_at=datetime.now(timezone.utc),
        properties={
            "keyType": "RSA",
            "keySize": 2048,
            "signatureAlgorithm": "UNKNOWN-CUSTOM-SIG-ALGO",
        },
    )

    assessments = resolve_asset_quantum_risk(asset)
    assert len(assessments) == 2

    by_sub = {a.subject_id: a for a in assessments}
    # Known RSA
    rsa_ass = by_sub["sub-rsa"]
    assert rsa_ass.risk_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert rsa_ass.migration_priority in ("P0", "P1", "P2", "P3", "MONITOR")
    assert rsa_ass.confidence == 1.0

    # Unknown custom sig
    unk_ass = by_sub["sub-unknown-custom-sig-algo"]
    assert unk_ass.risk_tier == "UNKNOWN"
    assert unk_ass.migration_priority == "UNKNOWN"
    assert unk_ass.confidence == 0.2


# ---------------------------------------------------------------------------
# Task 3: Integration, Error Propagation & Empty Results in QuantumRiskStage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_quantum_risk_stage_resilient_to_single_asset_error():
    """Verify a resolution exception on one asset does not abort remaining assets and reports partial status."""
    scan_id = str(uuid.uuid4())
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")

    inventory = CanonicalInventory(scan_id=scan_id, target="pnb.bank")

    # Asset 1: Valid
    valid_asset = CanonicalAsset(
        scan_id=scan_id,
        asset_type=AssetType.CERTIFICATE,
        name="valid-cert",
        observed_at=datetime.now(timezone.utc),
        properties={"keyType": "RSA", "keySize": 2048},
    )
    # Asset 2: Corrupted object that raises on property iteration
    mock_bad_asset = MagicMock(spec=CanonicalAsset)
    mock_bad_asset.asset_id = "bad-asset-id"
    mock_bad_asset.scan_id = scan_id
    mock_bad_asset.properties = MagicMock()
    mock_bad_asset.properties.items = MagicMock(side_effect=RuntimeError("Data corruption in asset properties"))

    inventory.assets.certificates.append(valid_asset)
    inventory.assets.certificates.append(mock_bad_asset)
    ctx.canonical_inventory = inventory

    stage = QuantumRiskStage()
    result = await stage.execute(ctx)

    # Valid asset must still be assessed
    assert len(result.data["quantum_assessments"]) == 1
    assert result.data["quantum_assessments"][0]["subject_id"] == "sub-rsa"

    # Stage status must be partial
    assert result.status == "partial"
    assert "bad-asset-id" in result.data["resolution_errors"]
    assert "Data corruption" in result.data["resolution_errors"]["bad-asset-id"]

    # Context and result must record the resolution failure
    assert hasattr(ctx, "quantum_resolution_errors")
    assert "bad-asset-id" in ctx.quantum_resolution_errors


@pytest.mark.asyncio
async def test_quantum_risk_stage_empty_crypto_inventory():
    """Verify a scan with no eligible cryptographic evidence is not falsely reported as SAFE."""
    scan_id = str(uuid.uuid4())
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")

    inventory = CanonicalInventory(scan_id=scan_id, target="pnb.bank")
    # Add non-crypto host asset
    host_asset = CanonicalAsset(
        scan_id=scan_id,
        asset_type=AssetType.HOST,
        name="192.168.1.1",
        observed_at=datetime.now(timezone.utc),
        properties={"ip": "192.168.1.1"},
    )
    inventory.assets.hosts.append(host_asset)
    ctx.canonical_inventory = inventory

    stage = QuantumRiskStage()
    result = await stage.execute(ctx)

    assert result.status == "completed"
    assert len(result.data["quantum_assessments"]) == 0

    # Risk level must be 'unknown', confidence 0.0, unknown_coverage 1.0
    assert ctx.quantum_score["risk_level"] == "unknown"
    assert ctx.quantum_score["confidence"] == 0.0
    assert ctx.quantum_score["unknown_coverage"] == 1.0
