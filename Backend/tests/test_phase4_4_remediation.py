"""
QuantumShield — Phase 4.4 Regression and End-to-End Tests
PQC Recommendation Validation and Risk-to-Roadmap Integration

Covers:
1. Role-compatible KEM recommendations (NIST FIPS 203: ML-KEM).
2. Role-compatible Digital Signature recommendations (NIST FIPS 204: ML-DSA, NIST FIPS 205: SLH-DSA).
3. Symmetric encryption handling (AES-128 upgrade vs AES-256 monitor).
4. Hash function handling (MD5/SHA-1 upgrade vs SHA-256 monitor).
5. Hybrid key establishment recommendation (X25519-ML-KEM-768, IETF Draft TLS Hybrid).
6. Already-migrated post-quantum assets (ML-KEM, ML-DSA, SLH-DSA -> ActionType.MONITOR).
7. Unknown / ambiguous algorithm handling (confidence penalty <= 0.2, ActionType.INVENTORY).
8. Missing catalogue entries / role mismatches.
9. Risk-to-roadmap end-to-end data trace (Canonical Asset -> Context -> Quantum Risk -> Roadmap Item).
10. Empty and partial inventory semantics.
11. Facade and API route retrieval with mocked MongoDB.
12. Regression compatibility with Phases 4.1, 4.2, and 4.3.

NOTE: All database tests in this module use in-memory mocks (AsyncMock/MagicMock)
as live MongoDB instances are not assumed to be running in this environment.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalFinding,
    CanonicalProperty,
)
from app.scanner.convergence.enums import (
    AssetType,
    RiskLevel,
    ObservationStatus,
)
from app.scanner.convergence.aggregation import CanonicalInventory
from app.scanner.quantum.catalogue import CatalogueManager
from app.scanner.quantum.models import (
    QuantumTimeline,
    TimeValue,
    QuantumRiskAssessment,
    AssetQuantumRiskSummary,
)
from app.scanner.quantum.quantum_risk_engine import assess_quantum_risk
from app.scanner.quantum.context_resolver import resolve_asset_quantum_risk
from app.scanner.quantum.aggregation_engine import aggregate_asset_risk
from app.scanner.roadmap.adapters.phase3_adapter import (
    build_phase3_context,
    NormalizedFindingContext,
    NormalizedAssetContext,
)
from app.scanner.roadmap.adapters.phase4_adapter import Phase4Context
from app.scanner.roadmap.decision_engine import PqcDecisionEngine, RecommendationModel
from app.scanner.roadmap.item_generator import generate_roadmap
from app.scanner.roadmap.models import (
    ActionType,
    EffortLevel,
    PriorityTier,
    RoadmapTrack,
    TieredSecurityRoadmap,
)
from app.scanner.roadmap.facade import build_roadmap_from_scan
from app.main import app
from app.db.connection import get_database


def _make_timeline(tm: float = 2.0, tc: float = 5.0, tq: float = 15.0) -> QuantumTimeline:
    return QuantumTimeline(
        Tm=TimeValue(value=tm, unit="years", source="test", confidence=0.8),
        Tc=TimeValue(value=tc, unit="years", source="test", confidence=0.8),
        Tq=TimeValue(value=tq, unit="years", source="test", confidence=0.8),
    )


# =========================================================================
# 1. Role-Compatible KEM Recommendations (NIST FIPS 203)
# =========================================================================

def test_kem_recommendation_for_ecdh_key_establishment():
    """Verify key exchange (ECDHE) receives a role-compatible KEM (ML-KEM) under FIPS 203."""
    finding = NormalizedFindingContext(
        finding_id="find-kex-01",
        finding_type="VULNERABLE_KEY_EXCHANGE",
        severity="HIGH",
        confidence=0.9,
        state="OBSERVED",
        evidence=["Observed TLS 1.3 KeyShare: ECDHE with X25519"],
        details={"algorithm": "ECDHE-X25519", "role": "KEY_ESTABLISHMENT"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-host-01",
                asset_type="HOST",
                name="api.gateway.bank",
                business_criticality="HIGH",
                internet_exposure="INTERNET_FACING",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.cryptographic_role == "KEY_ESTABLISHMENT"
    assert rec.recommended_candidate is not None
    # Must be an ML-KEM candidate (FIPS 203)
    assert "ml-kem" in rec.recommended_candidate.lower() or "kyber" in rec.recommended_candidate.lower()
    # Must NOT recommend a signature scheme
    assert "dsa" not in rec.recommended_candidate.lower()
    # Verify FIPS 203 standards reference
    assert any("203" in std for std in rec.standards_references)
    # Check that signature candidates in catalogue were rejected for role mismatch
    rejected_reasons = {r["candidate_id"]: r["reason"] for r in rec.rejected_candidates}
    for cand_id, reason in rejected_reasons.items():
        if "sig" in cand_id or "dsa" in cand_id:
            assert "ROLE_MISMATCH" in reason.upper()


def test_catalogue_fips_203_kem_parameter_sets():
    """Verify the PQC catalogue includes ML-KEM parameter sets standardized under FIPS 203."""
    kem_512 = CatalogueManager.get_by_id("pqc.kem.ml-kem-512")
    kem_768 = CatalogueManager.get_by_id("pqc.kem.ml-kem-768")
    kem_1024 = CatalogueManager.get_by_id("pqc.kem.ml-kem-1024")

    assert kem_512 is not None and kem_512.standardization_status == "STANDARDIZED"
    assert kem_768 is not None and kem_768.standardization_status == "STANDARDIZED"
    assert kem_1024 is not None and kem_1024.standardization_status == "STANDARDIZED"

    assert kem_512.standard_reference == "FIPS 203"
    assert kem_768.standard_reference == "FIPS 203"
    assert kem_1024.standard_reference == "FIPS 203"
    assert kem_768.cryptographic_role == "KEY_ESTABLISHMENT"


# =========================================================================
# 2. Role-Compatible Digital Signature Recommendations (NIST FIPS 204 & 205)
# =========================================================================

def test_signature_recommendation_for_rsa_digital_signature():
    """Verify digital signature (RSA-2048 cert) receives ML-DSA under FIPS 204."""
    finding = NormalizedFindingContext(
        finding_id="find-sig-01",
        finding_type="QUANTUM_VULNERABLE_CERTIFICATE",
        severity="HIGH",
        confidence=0.95,
        state="OBSERVED",
        evidence=["Observed X.509 leaf certificate signed with RSA-2048"],
        details={"algorithm": "RSA-2048", "role": "DIGITAL_SIGNATURE"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-cert-01",
                asset_type="CERTIFICATE",
                name="CN=portal.bank",
                business_criticality="CRITICAL",
                internet_exposure="INTERNET_FACING",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.cryptographic_role == "DIGITAL_SIGNATURE"
    assert rec.recommended_candidate is not None
    # Must be a signature candidate (FIPS 204: ML-DSA or FIPS 205: SLH-DSA)
    assert "dsa" in rec.recommended_candidate.lower() or "dilithium" in rec.recommended_candidate.lower()
    # Must NOT recommend a KEM
    assert "kem" not in rec.recommended_candidate.lower()
    # Verify FIPS 204 or 205 standards reference
    assert any("204" in std or "205" in std for std in rec.standards_references)


def test_catalogue_fips_205_slh_dsa_presence_and_eligibility():
    """Verify stateless hash-based signature SLH-DSA under FIPS 205 is standardized in catalogue."""
    slh = CatalogueManager.get_by_id("pqc.sig.slh-dsa-sha2-128s")
    assert slh is not None
    assert slh.standardization_status == "STANDARDIZED"
    assert slh.standard_reference == "FIPS 205"
    assert slh.cryptographic_role == "DIGITAL_SIGNATURE"
    assert slh.family == "SLH-DSA"


# =========================================================================
# 3. Symmetric Encryption & Hash Function Handling
# =========================================================================

def test_symmetric_encryption_aes_128_requires_upgrade():
    """Verify AES-128 requires key upgrade to AES-256 for Grover resistance, not lattice PQC."""
    finding = NormalizedFindingContext(
        finding_id="find-sym-01",
        finding_type="DEPRECATED_SYMMETRIC_KEY_LENGTH",
        severity="MEDIUM",
        confidence=0.9,
        state="OBSERVED",
        details={"algorithm": "AES-128-CBC", "role": "SYMMETRIC_ENCRYPTION"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-db-01",
                asset_type="DATA",
                name="Customer_Records",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.cryptographic_role == "SYMMETRIC_ENCRYPTION"
    assert rec.recommended_candidate == "AES-256-GCM"
    assert "Grover" in rec.rationale
    assert "SP 800-131A" in rec.standards_references[0] or "FIPS 197" in rec.standards_references[0]

    # Verify RoadmapItem creation
    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s1", target="test.com"))
    p3_ctx.findings = [finding]
    p4_ctx = Phase4Context([], [])
    roadmap = generate_roadmap("test.com", p3_ctx, p4_ctx)

    item = roadmap.items[0]
    assert item.action_type == ActionType.UPGRADE
    assert item.track == RoadmapTrack.CLASSICAL_SECURITY
    assert "AES-256" in item.title


def test_symmetric_encryption_aes_256_monitor_only():
    """Verify AES-256 meets Grover resistance requirements and only requires monitoring."""
    finding = NormalizedFindingContext(
        finding_id="find-sym-02",
        finding_type="STRONG_SYMMETRIC_CIPHER",
        severity="SAFE",
        confidence=0.9,
        state="OBSERVED",
        details={"algorithm": "AES-256-GCM", "role": "SYMMETRIC_ENCRYPTION"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-db-02",
                asset_type="DATA",
                name="Encrypted_Vault",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.cryptographic_role == "SYMMETRIC_ENCRYPTION"
    assert rec.recommended_candidate is None

    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s1", target="test.com"))
    p3_ctx.findings = [finding]
    p4_ctx = Phase4Context([], [])
    roadmap = generate_roadmap("test.com", p3_ctx, p4_ctx)

    item = roadmap.items[0]
    assert item.action_type == ActionType.MONITOR
    assert item.tier == PriorityTier.LOW
    assert item.urgency == "LOW"


def test_hash_function_weak_md5_upgrade_vs_sha256_monitor():
    """Verify weak MD5 requires upgrade while SHA-256 requires monitoring."""
    finding_md5 = NormalizedFindingContext(
        finding_id="find-hash-01",
        finding_type="WEAK_HASH",
        severity="HIGH",
        confidence=0.9,
        state="OBSERVED",
        details={"algorithm": "MD5", "role": "HASH"},
    )
    rec_md5 = PqcDecisionEngine.generate_recommendation(finding_md5, [])
    assert rec_md5.recommended_candidate == "SHA-256"

    finding_sha = NormalizedFindingContext(
        finding_id="find-hash-02",
        finding_type="SECURE_HASH",
        severity="SAFE",
        confidence=0.9,
        state="OBSERVED",
        details={"algorithm": "SHA-256", "role": "HASH"},
    )
    rec_sha = PqcDecisionEngine.generate_recommendation(finding_sha, [])
    assert rec_sha.recommended_candidate is None


# =========================================================================
# 4. Hybrid Key Establishment (X25519-ML-KEM-768)
# =========================================================================

def test_hybrid_key_establishment_generates_validate_action():
    """Verify hybrid key exchange is recognized as hybrid, references IETF draft, and yields ActionType.VALIDATE."""
    finding = NormalizedFindingContext(
        finding_id="find-hyb-01",
        finding_type="HYBRID_KEY_EXCHANGE",
        severity="SAFE",
        confidence=0.95,
        state="OBSERVED",
        evidence=["Observed TLS 1.3 key_share: X25519MLKEM768"],
        details={"algorithm": "X25519-ML-KEM-768", "role": "KEY_ESTABLISHMENT"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-edge-01",
                asset_type="HOST",
                name="edge.bank.com",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.is_hybrid is True
    assert rec.is_already_migrated is False
    assert rec.recommended_candidate is None
    # Crucial standard validation: hybrid combinations are IETF Drafts, NOT FIPS-approved
    assert "IETF Draft TLS Hybrid" in rec.standards_references

    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s1", target="bank.com"))
    p3_ctx.findings = [finding]
    p4_ctx = Phase4Context([], [])
    roadmap = generate_roadmap("bank.com", p3_ctx, p4_ctx)

    item = roadmap.items[0]
    assert item.action_type == ActionType.VALIDATE
    assert item.track == RoadmapTrack.QUANTUM_MIGRATION
    assert item.tier == PriorityTier.LOW
    assert item.urgency == "LOW"


# =========================================================================
# 5. Already-Migrated Post-Quantum Assets
# =========================================================================

def test_already_migrated_pqc_asset_generates_monitor_action():
    """Verify pure PQC implementation (ML-KEM-768) generates MONITOR action without migration alarm."""
    finding = NormalizedFindingContext(
        finding_id="find-pqc-01",
        finding_type="PQC_KEY_EXCHANGE",
        severity="SAFE",
        confidence=0.95,
        state="OBSERVED",
        details={"algorithm": "ML-KEM-768", "role": "KEY_ESTABLISHMENT"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-pqc-01",
                asset_type="HOST",
                name="pqc.internal.bank",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.is_already_migrated is True
    assert rec.is_hybrid is False
    assert rec.recommended_candidate is None
    assert "FIPS 203" in rec.standards_references

    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s1", target="bank.com"))
    p3_ctx.findings = [finding]
    p4_ctx = Phase4Context([], [])
    roadmap = generate_roadmap("bank.com", p3_ctx, p4_ctx)

    item = roadmap.items[0]
    assert item.action_type == ActionType.MONITOR
    assert item.track == RoadmapTrack.QUANTUM_MIGRATION
    assert item.tier == PriorityTier.LOW
    assert item.urgency == "LOW"


# =========================================================================
# 6. Unknown / Ambiguous Algorithm Handling
# =========================================================================

def test_unknown_algorithm_preserves_uncertainty_and_generates_inventory_action():
    """Verify unknown algorithm data produces ActionType.INVENTORY with confidence <= 0.2."""
    finding = NormalizedFindingContext(
        finding_id="find-unk-01",
        finding_type="AMBIGUOUS_CRYPTO",
        severity="UNKNOWN",
        confidence=0.8,
        state="OBSERVED",
        details={"algorithm": "UNKNOWN", "role": "UNKNOWN"},
        asset_contexts=[
            NormalizedAssetContext(
                asset_id="asset-unk-01",
                asset_type="HOST",
                name="legacy.bank",
            )
        ]
    )

    rec = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
    assert rec.cryptographic_role == "INSUFFICIENT_CONTEXT"
    assert rec.recommended_candidate is None
    assert rec.confidence <= 0.2

    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s1", target="legacy.bank"))
    p3_ctx.findings = [finding]
    p4_ctx = Phase4Context([], [])
    roadmap = generate_roadmap("legacy.bank", p3_ctx, p4_ctx)

    item = roadmap.items[0]
    assert item.action_type == ActionType.INVENTORY
    assert item.track == RoadmapTrack.CROSS_CUTTING
    assert item.tier == PriorityTier.LOW
    assert item.drivers.confidence <= 0.2


# =========================================================================
# 7. End-to-End Data Trace: Canonical Asset -> Context -> Quantum Risk -> Roadmap
# =========================================================================

def test_risk_to_roadmap_end_to_end_trace():
    """
    Traces an authoritative classical cryptographic asset through the full pipeline:
    1. CanonicalAsset & Evidence
    2. Context resolution and algorithm normalization
    3. Quantum-risk assessment
    4. Asset aggregation
    5. Phase 3 & Phase 4 context adaptors
    6. PQC decision engine recommendation
    7. Authoritative Roadmap Item generation
    """
    scan_id = "scan-e2e-44"
    asset_id = "asset-tls-kex-101"
    now = datetime.now(timezone.utc)

    # 1. Canonical Asset
    asset = CanonicalAsset(
        scan_id=scan_id,
        asset_id=asset_id,
        asset_type=AssetType.HOST,
        name="secure-banking.pnb.in",
        observed_at=now,
        properties={
            "algorithm": CanonicalProperty(name="algorithm", canonical_value="ECDHE", raw_value="ECDHE-RSA-AES128-GCM-SHA256", source="tls"),
            "keySize": CanonicalProperty(name="keySize", canonical_value=256, raw_value="256", source="tls"),
            "business_criticality": CanonicalProperty(name="business_criticality", canonical_value="CRITICAL", raw_value="CRITICAL", source="tag"),
            "internet_exposure": CanonicalProperty(name="internet_exposure", canonical_value="INTERNET_FACING", raw_value="true", source="net"),
        }
    )

    # 2. Context Resolution & Normalization
    assessments = resolve_asset_quantum_risk(asset)
    assert len(assessments) > 0
    assessment = assessments[0]
    assert assessment.asset_id == asset_id
    assert assessment.scan_id == scan_id
    assert assessment.hndl.key_exchange_exposure is True
    assert len(assessment.evidence) > 0

    # 3. Explicit Timeline Assessment for Mosca Critical Urgency
    timeline = _make_timeline(tm=3.0, tc=10.0, tq=12.0) # Mosca margin: 3 + 10 - 12 = +1.0 (CRITICAL_URGENCY)
    critical_assessment = assess_quantum_risk(
        asset_id=asset.asset_id,
        algorithm_name="ECDHE",
        key_size=256,
        key_exchange_role=True,
        timeline=timeline,
        data_sensitivity="HIGH",
        business_criticality="CRITICAL",
        evidence=assessment.evidence,
        scan_id=scan_id
    )
    assert critical_assessment.asset_id == asset_id
    assert critical_assessment.scan_id == scan_id
    assert critical_assessment.mosca.status == "CRITICAL_URGENCY"

    # 4. Aggregation
    summary = aggregate_asset_risk(asset_id=asset_id, assessments=[critical_assessment])
    assert summary.asset_id == asset_id
    assert summary.mosca.status == "CRITICAL_URGENCY"

    # 5. Phase 3 & 4 Adapters
    inventory = CanonicalInventory(scan_id=scan_id, target="secure-banking.pnb.in")
    inventory.assets.hosts.append(asset)
    finding = CanonicalFinding(
        scan_id=scan_id,
        finding_id="finding-crypto-101",
        finding_type="QUANTUM_VULNERABLE_KEX",
        title="Quantum Vulnerable Key Exchange",
        description="ECDHE key exchange vulnerable to Shor's algorithm",
        asset_refs=[asset_id],
        evidence_refs=["tls.kex.ecdh_rsa"],
        severity=RiskLevel.HIGH,
        confidence=0.9,
        status=ObservationStatus.OBSERVED,
        details={"algorithm": "ECDHE", "role": "KEY_ESTABLISHMENT"}
    )
    inventory.findings.append(finding)

    p3_ctx = build_phase3_context(inventory)
    assert p3_ctx.scan_id == scan_id
    assert len(p3_ctx.findings) == 1
    assert p3_ctx.findings[0].asset_contexts[0].business_criticality == "CRITICAL"

    p4_ctx = Phase4Context([assessment], [summary])

    # 6. Roadmap Generation
    roadmap = generate_roadmap("secure-banking.pnb.in", p3_ctx, p4_ctx)

    # 7. Verification of Consistency Across the Entire Pipeline
    assert roadmap.scan_id == scan_id
    assert len(roadmap.items) == 1
    item = roadmap.items[0]

    assert asset_id in item.asset_ids
    assert "finding-crypto-101" in item.finding_ids
    assert item.track == RoadmapTrack.QUANTUM_MIGRATION
    assert item.action_type == ActionType.MIGRATE
    assert "ml-kem" in item.title.lower() or "kyber" in item.title.lower()
    assert item.tier == PriorityTier.CRITICAL
    assert item.urgency == "CRITICAL_URGENCY"
    assert "tls.kex.ecdh_rsa" in item.provenance


# =========================================================================
# 8. Empty and Partial Inventory Semantics
# =========================================================================

def test_empty_inventory_semantics():
    """Verify empty canonical inventory produces an empty roadmap with zero tasks."""
    inventory = CanonicalInventory(scan_id="scan-empty-01", target="empty.bank")
    p3_ctx = build_phase3_context(inventory)
    p4_ctx = Phase4Context([], [])

    roadmap = generate_roadmap("empty.bank", p3_ctx, p4_ctx)
    assert roadmap.items == []
    assert roadmap.statistics.total_tasks == 0
    assert roadmap.statistics.critical_pqc_tasks == 0


def test_partial_inventory_unknown_semantics():
    """Verify partial scan with unknown finding is distinguished from a verified safe scan."""
    finding_unknown = NormalizedFindingContext(
        finding_id="f-unk",
        finding_type="UNVERIFIED_CIPHER",
        severity="UNKNOWN",
        confidence=0.15,
        state="OBSERVED",
        details={"algorithm": "", "role": ""},
    )
    p3_ctx = build_phase3_context(CanonicalInventory(scan_id="s-part", target="part.bank"))
    p3_ctx.findings = [finding_unknown]
    p4_ctx = Phase4Context([], [])

    roadmap = generate_roadmap("part.bank", p3_ctx, p4_ctx)
    assert len(roadmap.items) == 1
    item = roadmap.items[0]
    # Distinguishable: action_type is INVENTORY, not MONITOR or MIGRATE
    assert item.action_type == ActionType.INVENTORY
    assert item.drivers.confidence <= 0.2


# =========================================================================
# 9. Facade and API Route Retrieval (Mocked MongoDB)
# =========================================================================

@pytest.mark.asyncio
async def test_build_roadmap_from_scan_facade_mocked_db():
    """
    Verify build_roadmap_from_scan successfully parses MongoDB scan document
    using AsyncMock (mocked MongoDB).
    """
    scan_id = "scan-facade-mock-01"
    domain = "facade.test.bank"

    mock_db = MagicMock()
    # Mock cursor async iterators
    async def empty_cursor():
        if False: yield {}

    mock_cursor1 = MagicMock()
    mock_cursor1.__aiter__ = empty_cursor
    mock_cursor2 = MagicMock()
    mock_cursor2.__aiter__ = empty_cursor
    mock_cursor3 = MagicMock()
    mock_cursor3.__aiter__ = empty_cursor

    mock_db.__getitem__.side_effect = lambda coll: {
        "quantum_assessments": MagicMock(find=MagicMock(return_value=mock_cursor1)),
        "quantum_asset_summaries": MagicMock(find=MagicMock(return_value=mock_cursor2)),
        "migration_tasks": MagicMock(find=MagicMock(return_value=mock_cursor3)),
    }.get(coll, MagicMock())

    scan_doc = {
        "scan_id": scan_id,
        "domain": domain,
        "status": "COMPLETED",
        "canonical_inventory": {
            "scan_id": scan_id,
            "target": domain,
            "assets": {"hosts": [], "services": [], "endpoints": [], "certificates": [], "software": [], "data": []},
            "findings": [
                {
                    "scan_id": scan_id,
                    "finding_id": "f-facade-01",
                    "finding_type": "WEAK_HASH",
                    "title": "Deprecated Hash Algorithm",
                    "description": "MD5 hash is cryptographically broken",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "status": "OBSERVED",
                    "details": {"algorithm": "MD5", "role": "HASH"}
                }
            ]
        }
    }

    roadmap = await build_roadmap_from_scan(mock_db, scan_doc)
    assert isinstance(roadmap, TieredSecurityRoadmap)
    assert roadmap.scan_id == scan_id
    assert len(roadmap.items) == 1
    assert roadmap.items[0].action_type == ActionType.UPGRADE


def test_security_roadmap_api_endpoint_mocked_db():
    """
    Verify /api/v1/security-roadmap/scan/{scan_id} HTTP route contract using
    FastAPI TestClient and mocked MongoDB database dependency.
    """
    scan_id = "scan-api-mock-02"
    domain = "api.test.bank"

    mock_scan_doc = {
        "scan_id": scan_id,
        "domain": domain,
        "status": "COMPLETED",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "quantum_score": {"risk_level": "HIGH", "score": 85.0},
        "canonical_inventory": {
            "scan_id": scan_id,
            "target": domain,
            "assets": {"hosts": [], "services": [], "endpoints": [], "certificates": [], "software": [], "data": []},
            "findings": [
                {
                    "scan_id": scan_id,
                    "finding_id": "f-api-01",
                    "finding_type": "QUANTUM_VULNERABLE_KEX",
                    "title": "Vulnerable Key Exchange",
                    "description": "ECDHE is vulnerable to quantum cryptanalysis",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "status": "OBSERVED",
                    "details": {"algorithm": "ECDHE-RSA", "role": "KEY_ESTABLISHMENT"}
                }
            ]
        }
    }

    mock_db = MagicMock()
    mock_db["scans"].find_one = AsyncMock(return_value=mock_scan_doc)

    async def empty_cursor():
        if False: yield {}

    mock_c = MagicMock()
    mock_c.__aiter__ = empty_cursor
    mock_db["quantum_assessments"].find.return_value = mock_c
    mock_db["quantum_asset_summaries"].find.return_value = mock_c
    mock_db["migration_tasks"].find.return_value = mock_c

    with patch("app.api.routers.crypto_cbom.get_database", return_value=mock_db):
        client = TestClient(app)
        response = client.get(f"/api/v1/security-roadmap/scan/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["domain"] == domain
        assert len(data["items"]) == 1
        assert data["items"][0]["action_type"] == "MIGRATE"
        assert "disclaimer" in data


# =========================================================================
# 10. Backward Compatibility with Phase 4.1, 4.2, and 4.3 Components
# =========================================================================

def test_backward_compatibility_with_prior_phase_components():
    """Verify that prior phase engines and models remain fully compatible."""
    # Phase 4.3 Mosca Boundary: margin <= -2.0 is SAFE_MARGIN, -2.0 < margin < 0 is BORDERLINE
    from app.scanner.quantum.mosca_engine import calculate_mosca_assessment
    t_safe = _make_timeline(tm=3.0, tc=10.0, tq=15.0)  # margin = 3 + 10 - 15 = -2.0
    m_safe = calculate_mosca_assessment(t_safe)
    assert m_safe.status == "SAFE_MARGIN"

    t_border = _make_timeline(tm=4.0, tc=10.0, tq=15.0)  # margin = 4 + 10 - 15 = -1.0
    m_border = calculate_mosca_assessment(t_border)
    assert m_border.status == "BORDERLINE"

    # Phase 4.2 Aggregation with Unknown Risk
    from app.scanner.quantum.aggregation_engine import aggregate_organization_risk
    org_summary = aggregate_organization_risk([])
    assert org_summary.total_assets == 0
    assert org_summary.unknown_coverage == 1.0
