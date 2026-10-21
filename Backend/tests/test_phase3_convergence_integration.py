"""
Phase 3.2 Controlled Implementation Tests:
Adapter Contracts, Canonical Inventory Traversal, and Pipeline Integration.

Covers Workstream D requirements:
1. TLS adapter conversion from actual upstream dictionary schema.
2. Crypto adapter conversion from actual upstream dictionary schema.
3. Missing and malformed adapter fields handling.
4. Canonical asset traversal across multiple categories.
5. Empty inventory handling.
6. QuantumRiskStage receiving a valid canonical inventory.
7. ConvergenceStage execution in actual pipeline ordering.
8. Adapter failure producing observable partial-result or error state.
9. Preservation of legacy CBOM and Annexure-A behavior.
"""

import uuid
import pytest
from datetime import datetime, timezone
from typing import List

from app.scanner.pipeline import ScanContext, DualTrackPipelineManager, PipelineManager, ScanStage, StageResult, StageCriticality, MergeStrategy
from app.scanner.convergence.adapters import (
    TLSAdapter,
    CryptoAdapter,
    SASTAdapter,
    SCAAdapter,
    ContainerAdapter,
    ReconAdapter,
    NetworkAdapter,
)
from app.scanner.convergence.convergence_stage import ConvergenceStage
from app.scanner.convergence.aggregation import CanonicalInventoryBuilder, CanonicalInventory, InventoryAssets
from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalFinding, CanonicalEvidence, Identifier
from app.scanner.convergence.enums import AssetType, RiskLevel, ObservationStatus
from app.scanner.quantum.engine_stage import QuantumRiskStage
from app.scanner.engines.cbom_unification import CBOMUnificationEngine


# ---------------------------------------------------------------------------
# 1. TLS Adapter: Upstream dictionary schema conversion
# ---------------------------------------------------------------------------
def test_tls_adapter_dict_conversion():
    """Verify TLSAdapter correctly converts dicts produced by TLSCryptoEngine."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="pnb.bank")

    # Real dictionary structure output by TLSCryptoEngine.execute() (TLSProfile.model_dump())
    raw_tls_profile = {
        "host": "api.pnb.bank",
        "port": 443,
        "tls_versions_supported": {
            "TLSv1.2": True,
            "TLSv1.3": True,
            "TLSv1.0": False,
        },
        "accepted_ciphers": [
            {
                "name": "TLS_AES_256_GCM_SHA384",
                "primitive": "symmetric",
                "mode": "GCM",
                "crypto_functions": ["encryption", "mac"],
                "classical_security_level": 256,
                "oid": "2.16.840.1.101.3.4.1.45"
            }
        ],
        "cert_chain": [
            {
                "subject": "CN=api.pnb.bank, O=Punjab National Bank",
                "issuer": "CN=PNB Internal CA",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2025-01-01T00:00:00Z",
                "fingerprint_sha256": "1234567890abcdef" * 4,
                "sig_algorithm": "sha256WithRSAEncryption",
                "sig_algorithm_oid": "1.2.840.113549.1.1.11",
                "subject_public_key_ref": "rsa-pubkey-ref",
                "key_type": "RSA",
                "key_size": 2048
            }
        ],
        "confidence": "high"
    }
    ctx.tls_profiles.append(raw_tls_profile)

    adapter = TLSAdapter()
    assets, findings, evidence = adapter.process(ctx)

    assert len(adapter.conversion_errors) == 0

    # Service asset
    services = [a for a in assets if a.asset_type == AssetType.SERVICE]
    assert len(services) == 1
    assert services[0].name == "TLS Service api.pnb.bank:443"

    # Certificate asset
    certs = [a for a in assets if a.asset_type == AssetType.CERTIFICATE]
    assert len(certs) == 1
    assert certs[0].name == "CN=api.pnb.bank, O=Punjab National Bank"
    assert certs[0].properties["keyType"] == "RSA"
    assert certs[0].properties["keySize"] == 2048

    # Protocol assets (TLSv1.2 and TLSv1.3 enabled, TLSv1.0 skipped)
    protocols = [a for a in assets if a.asset_type == AssetType.PROTOCOL]
    assert len(protocols) == 2
    proto_names = {p.name for p in protocols}
    assert proto_names == {"TLSv1.2", "TLSv1.3"}

    # Algorithm asset
    algorithms = [a for a in assets if a.asset_type == AssetType.ALGORITHM]
    assert len(algorithms) == 1
    assert algorithms[0].name == "TLS_AES_256_GCM_SHA384"
    assert algorithms[0].properties["primitive"] == "symmetric"

    # Evidence verified (cert and cipher suite evidence)
    assert len(evidence) == 2
    assert {e.observation_type for e in evidence} == {"certificate", "cipher_suite"}


# ---------------------------------------------------------------------------
# 2. Crypto Adapter: Upstream dictionary schema conversion
# ---------------------------------------------------------------------------
def test_crypto_adapter_dict_conversion():
    """Verify CryptoAdapter converts dicts produced by CryptoAnalysisEngine."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="pnb.bank")

    # Real dictionary findings output by CryptoAnalysisEngine (CryptoFinding.model_dump())
    raw_findings = [
        {
            "host": "api.pnb.bank",
            "port": 443,
            "component": "cipher_kex",
            "algorithm": "ECDHE-RSA",
            "quantum_risk": "critical",
            "threat_vector": "Shor's algorithm breaks discrete logarithm",
            "hndl_risk": "CRITICAL",
            "nist_recommendation": "Migrate to ML-KEM / Kyber",
            "evidence": "ECDHE key exchange vulnerable to CRQC",
            "confidence": "high",
        },
        # Composite score row emitted by engine — must be skipped
        {
            "host": "api.pnb.bank",
            "port": 443,
            "component": "crypto_score",
            "algorithm": "composite",
            "quantum_risk": "info",
            "evidence": "Host crypto-quantum readiness score: 45/100",
            "confidence": "high",
        }
    ]
    ctx.crypto_findings.extend(raw_findings)

    adapter = CryptoAdapter()
    assets, findings, evidence = adapter.process(ctx)

    assert len(adapter.conversion_errors) == 0
    # Composite score was skipped, exactly 1 finding created
    assert len(findings) == 1
    cf = findings[0]
    assert cf.finding_type == "crypto_finding"
    assert cf.severity == RiskLevel.CRITICAL
    assert cf.confidence == 0.8
    assert cf.details["algorithm"] == "ECDHE-RSA"
    assert cf.details["hndl_risk"] == "CRITICAL"
    assert cf.details["nist_recommendation"] == "Migrate to ML-KEM / Kyber"

    assert len(evidence) == 1
    assert evidence[0].value == "cipher_kex:ECDHE-RSA"


# ---------------------------------------------------------------------------
# 3. Missing and malformed adapter fields
# ---------------------------------------------------------------------------
def test_missing_and_malformed_adapter_fields():
    """Verify adapters record observable conversion errors and do not crash on malformed data."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="test.local")

    # Malformed TLS records
    ctx.tls_profiles = [
        {"host": None, "port": 443},                         # missing host
        {"host": "valid.host", "port": "not-a-port"},       # invalid port
        {"host": "valid2.host", "port": -1},                # non-positive port
        "completely-invalid-non-dict-record",               # wrong type
        {
            "host": "valid3.host",
            "port": 443,
            "cert_chain": [{"subject": "CN=test"}],         # cert missing fingerprint
            "accepted_ciphers": [{"mode": "GCM"}]           # cipher missing name
        }
    ]

    tls_adapter = TLSAdapter()
    assets, findings, evidence = tls_adapter.process(ctx)
    # The valid3.host service was created, but invalid records and sub-records recorded errors
    assert len(tls_adapter.conversion_errors) >= 5
    assert any("missing required host or port" in e for e in tls_adapter.conversion_errors)
    assert any("invalid port" in e for e in tls_adapter.conversion_errors)
    assert any("missing required fingerprint" in e for e in tls_adapter.conversion_errors)
    assert any("missing valid name" in e for e in tls_adapter.conversion_errors)

    # Malformed Crypto findings
    ctx.crypto_findings = [
        {"component": None, "algorithm": "RSA"},            # missing component
        {"component": "cert", "algorithm": None},           # missing algorithm
        12345,                                              # wrong type
    ]
    crypto_adapter = CryptoAdapter()
    _, crypto_findings, _ = crypto_adapter.process(ctx)
    assert len(crypto_findings) == 0
    assert len(crypto_adapter.conversion_errors) == 3


# ---------------------------------------------------------------------------
# 4. Canonical asset traversal across multiple categories
# ---------------------------------------------------------------------------
def test_canonical_asset_traversal_across_categories():
    """Verify InventoryAssets and CanonicalInventory enumerate all assets without duplicates."""
    scan_id = str(uuid.uuid4())
    inventory = CanonicalInventory(scan_id=scan_id, target="pnb.bank")

    now = datetime.now(timezone.utc)
    host_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.HOST, name="pnb.bank", observed_at=now)
    svc_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.SERVICE, name="svc-443", observed_at=now)
    tech_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.APPLICATION, name="core-banking", observed_at=now)
    pkg_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.PACKAGE, name="openssl", version="1.1.1", observed_at=now)
    cert_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.CERTIFICATE, name="CN=pnb.bank", observed_at=now)
    algo_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.ALGORITHM, name="RSA-2048", observed_at=now)
    proto_asset = CanonicalAsset(scan_id=scan_id, asset_type=AssetType.PROTOCOL, name="TLSv1.3", observed_at=now)

    inventory.assets.hosts.append(host_asset)
    inventory.assets.services.append(svc_asset)
    inventory.assets.technologies.append(tech_asset)
    inventory.assets.packages.append(pkg_asset)
    inventory.assets.certificates.append(cert_asset)
    inventory.assets.algorithms.append(algo_asset)
    inventory.assets.protocols.append(proto_asset)

    # Add duplicate reference to verify deduplication in traversal
    inventory.assets.other.append(algo_asset)

    all_assets = inventory.all_assets()
    assert len(all_assets) == 7
    asset_ids = [a.asset_id for a in all_assets]
    assert len(asset_ids) == len(set(asset_ids))

    # Verify categories on inventory.assets remain distinct and intact
    assert len(inventory.assets.hosts) == 1
    assert len(inventory.assets.services) == 1
    assert len(inventory.assets.packages) == 1
    assert len(inventory.assets.certificates) == 1
    assert len(inventory.assets.algorithms) == 1


# ---------------------------------------------------------------------------
# 5. Empty inventory handling
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_empty_inventory_handling():
    """Verify empty canonical inventory executes safely and reports UNKNOWN coverage, not false safety."""
    scan_id = str(uuid.uuid4())
    ctx = ScanContext(scan_id=scan_id, domain="empty.example")
    ctx.canonical_inventory = CanonicalInventory(scan_id=scan_id, target="empty.example")

    assert ctx.canonical_inventory.all_assets() == []

    stage = QuantumRiskStage()
    result = await stage.execute(ctx)

    assert result.status == "completed"
    assert ctx.quantum_score["risk_level"] == "unknown"
    assert ctx.quantum_score["unknown_coverage"] == 1.0
    assert result.data["quantum_org_summary"]["total_assets"] == 0


# ---------------------------------------------------------------------------
# 6. QuantumRiskStage receiving a valid canonical inventory
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_quantum_risk_stage_with_valid_canonical_inventory():
    """Verify QuantumRiskStage iterates canonical inventory assets and computes risk assessments."""
    scan_id = str(uuid.uuid4())
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")

    inventory = CanonicalInventory(scan_id=scan_id, target="pnb.bank")
    asset = CanonicalAsset(
        scan_id=scan_id,
        asset_type=AssetType.SERVICE,
        name="api-gateway",
        observed_at=datetime.now(timezone.utc),
        properties={
            "crypto:tls:kex": "ECDHE",
            "crypto:tls:enc": "AES-128",
            "data_classification": "CONFIDENTIAL",
        }
    )
    inventory.assets.services.append(asset)
    ctx.canonical_inventory = inventory

    stage = QuantumRiskStage()
    result = await stage.execute(ctx)

    assert result.status == "completed"
    assert len(result.data["quantum_assessments"]) == 2
    assert len(result.data["quantum_asset_summaries"]) == 1
    assert "score" in ctx.quantum_score
    assert ctx.quantum_score["risk_level"] in ("critical", "high", "medium", "low", "safe", "unknown")


# ---------------------------------------------------------------------------
# 7. ConvergenceStage execution in actual pipeline ordering
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_convergence_stage_in_pipeline_ordering():
    """Verify Track C executes CBOMUnificationEngine -> ConvergenceStage -> QuantumRiskStage."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="pnb.bank")

    # Upstream data from Track A and B
    ctx.tls_profiles.append({
        "host": "pnb.bank",
        "port": 443,
        "tls_versions_supported": {"TLSv1.3": True},
        "accepted_ciphers": [{"name": "TLS_AES_256_GCM_SHA384"}],
        "cert_chain": [{
            "subject": "CN=pnb.bank",
            "fingerprint_sha256": "abcdef123456" * 5,
        }]
    })

    cbom_stage = CBOMUnificationEngine()
    conv_stage = ConvergenceStage()
    risk_stage = QuantumRiskStage()

    # Verify orders
    assert cbom_stage.order == 30
    assert conv_stage.order == 31
    assert risk_stage.order == 32

    # Run in DualTrack Track C pipeline
    track_c = PipelineManager(stages=[risk_stage, conv_stage, cbom_stage])
    # PipelineManager sorts stages by s.order: cbom (30) -> conv (31) -> risk (32)
    assert [s.name for s in track_c.stages] == ["cbom_unification", "convergence", "quantum_risk"]

    await track_c.run(ctx)

    # 1. CBOM Unification produced report
    assert ctx.unified_cbom_report is not None
    # 2. Convergence created canonical inventory
    assert ctx.canonical_inventory is not None
    assert len(ctx.canonical_inventory.all_assets()) > 0
    # 3. Quantum Risk stage consumed inventory
    assert ctx.quantum_score is not None
    assert "risk_level" in ctx.quantum_score


# ---------------------------------------------------------------------------
# 8. Adapter failure produces observable partial-result state
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_adapter_failure_produces_observable_partial_state():
    """Verify that an adapter error or malformed input produces an observable partial status."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="pnb.bank")

    # Add 1 valid profile and 1 malformed profile to trigger conversion errors in TLSAdapter
    ctx.tls_profiles.append({
        "host": "pnb.bank",
        "port": 443,
        "tls_versions_supported": {"TLSv1.3": True},
        "accepted_ciphers": [{"name": "TLS_AES_256_GCM_SHA384"}],
        "cert_chain": [{"subject": "CN=pnb.bank", "fingerprint_sha256": "aabbcc" * 10}]
    })
    ctx.tls_profiles.append({
        "host": None,
        "port": "not-a-port"
    })

    stage = ConvergenceStage()
    result = await stage.execute(ctx)

    # Observable partial status
    assert result.status == "partial"
    assert result.error is not None
    assert "adapter errors in: tls_engine" in result.error
    assert "tls_engine" in result.data["adapter_errors"]

    # Canonical inventory was still produced for valid data
    assert ctx.canonical_inventory is not None
    assert len(ctx.canonical_inventory.all_assets()) > 0


# ---------------------------------------------------------------------------
# 9. Preservation of legacy CBOM and Annexure-A behavior
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_preservation_of_legacy_cbom_and_annexure_a():
    """Verify CBOMUnificationEngine output is preserved with full schema compliance."""
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="pnb.bank")
    ctx.tls_profiles.append({
        "host": "pnb.bank",
        "port": 443,
        "tls_versions_supported": {"TLSv1.2": True, "TLSv1.3": True},
        "accepted_ciphers": [{"name": "TLS_AES_256_GCM_SHA384"}],
        "cert_chain": [{
            "subject": "CN=pnb.bank",
            "issuer": "CN=PNB CA",
            "fingerprint_sha256": "998877665544" * 5,
        }]
    })

    cbom_engine = CBOMUnificationEngine()
    result = await cbom_engine.execute(ctx)

    assert result.status == "completed"
    assert "unified_cbom_report" in result.data
    report = result.data["unified_cbom_report"]

    # Verify Annexure-A / CERT-IN standard CBOM top-level blocks
    assert "CBOM_Metadata" in report
    assert "Algorithms" in report
    assert "Certificates" in report
    assert "Keys" in report
    assert "Protocols" in report
    assert report["CBOM_Metadata"]["target"] == "pnb.bank"
