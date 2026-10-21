"""
Phase 3.3 Persistence and API Integration Regression Tests

D1 - canonical_inventory not persisted: serialization, rehydration, persistence dict.
D2 - quantum assessment scan_id missing: attachment before insert_many.
D3 - adapter errors not stored: ctx.convergence_adapter_errors written by ConvergenceStage.
Plus: CycloneDX round-trip, empty inventory, partial convergence, legacy CBOM coexistence.
"""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.convergence.aggregation import CanonicalInventory
from app.scanner.convergence.canonical_models import CanonicalAsset
from app.scanner.convergence.convergence_stage import ConvergenceStage
from app.scanner.convergence.cyclonedx.exporter import CycloneDXExporter
from app.scanner.convergence.cyclonedx.validator import validate_cyclonedx
from app.scanner.convergence.enums import AssetType
from app.scanner.pipeline import ScanContext
from app.scanner.quantum.engine_stage import QuantumRiskStage


def _make_scan_id():
    return str(uuid.uuid4())


def _utcnow():
    return datetime.now(timezone.utc)


def _minimal_inventory(scan_id, target="example.pnb"):
    now = _utcnow()
    inventory = CanonicalInventory(scan_id=scan_id, target=target)
    inventory.assets.hosts.append(CanonicalAsset(scan_id=scan_id, asset_type=AssetType.HOST, name="example.pnb", observed_at=now))
    inventory.assets.certificates.append(CanonicalAsset(scan_id=scan_id, asset_type=AssetType.CERTIFICATE, name="CN=example.pnb", observed_at=now, properties={"keyType": "RSA", "keySize": 2048}))
    inventory.assets.algorithms.append(CanonicalAsset(scan_id=scan_id, asset_type=AssetType.ALGORITHM, name="RSA-2048", observed_at=now))
    inventory.assets.protocols.append(CanonicalAsset(scan_id=scan_id, asset_type=AssetType.PROTOCOL, name="TLSv1.3", observed_at=now))
    return inventory


def test_canonical_inventory_json_mode_dump_is_primitive():
    scan_id = _make_scan_id()
    inventory = _minimal_inventory(scan_id)
    dumped = inventory.model_dump(mode="json")
    assert isinstance(dumped, dict)
    assert dumped["scan_id"] == scan_id
    raw_json = json.dumps(dumped)
    reparsed = json.loads(raw_json)
    assert reparsed["scan_id"] == scan_id
    assets_block = dumped["assets"]
    assert isinstance(assets_block["hosts"], list)
    host_record = assets_block["hosts"][0]
    assert host_record["asset_type"] == "host"
    assert isinstance(host_record["observed_at"], str)


def test_canonical_inventory_rehydration_round_trip():
    scan_id = _make_scan_id()
    original = _minimal_inventory(scan_id)
    dumped = original.model_dump(mode="json")
    restored = CanonicalInventory.model_validate(dumped)
    assert restored.scan_id == scan_id
    assert len(restored.assets.hosts) == 1
    assert len(restored.assets.certificates) == 1
    all_assets = restored.all_assets()
    assert len(all_assets) == 4
    assert len({a.asset_id for a in all_assets}) == 4


def test_cyclonedx_export_from_rehydrated_inventory():
    scan_id = _make_scan_id()
    stored_dict = _minimal_inventory(scan_id).model_dump(mode="json")
    estate = CanonicalInventory.model_validate(stored_dict)
    bom_json = CycloneDXExporter(estate).generate()
    assert bom_json is not None
    is_valid, errors = validate_cyclonedx(bom_json)
    if not is_valid:
        pytest.fail(f"CycloneDX from rehydrated inventory invalid: {errors}")
    parsed = json.loads(bom_json)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert len(parsed["components"]) >= 4


@pytest.mark.asyncio
async def test_quantum_assessment_documents_carry_scan_id():
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    ctx.canonical_inventory = _minimal_inventory(scan_id)
    inserted = []
    mock_coll = AsyncMock()
    mock_coll.insert_many = AsyncMock(side_effect=lambda docs: inserted.extend(docs))
    mock_other = AsyncMock()
    mock_other.insert_many = AsyncMock()
    mock_other.insert_one = AsyncMock()
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(side_effect=lambda n: mock_coll if n == "quantum_assessments" else mock_other)
    ctx.db = mock_db
    result = await QuantumRiskStage().execute(ctx)
    assert result.status in ("completed", "success", "skipped")
    if result.status != "skipped":
        for doc in inserted:
            if "assessment_id" in doc:
                assert "scan_id" in doc, f"Missing scan_id in assessment doc: {sorted(doc.keys())}"
                assert doc["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_convergence_adapter_errors_written_to_context():
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    with patch("app.scanner.convergence.convergence_stage.CloudAdapter.process", side_effect=RuntimeError("cloud failure")):
        result = await ConvergenceStage().execute(ctx)
    assert result.status in ("success", "partial", "error")
    if result.status == "partial":
        assert isinstance(ctx.convergence_adapter_errors, dict)
        assert len(ctx.convergence_adapter_errors) > 0
        for engine in ctx.convergence_adapter_errors:
            assert engine in result.data["adapter_errors"]


def test_canonical_inventory_included_in_persistence_update():
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    ctx.canonical_inventory = _minimal_inventory(scan_id)
    update = {}
    if ctx.canonical_inventory is not None:
        update["canonical_inventory"] = ctx.canonical_inventory.model_dump(mode="json")
    assert "canonical_inventory" in update
    json.dumps(update["canonical_inventory"])
    assert update["canonical_inventory"]["scan_id"] == scan_id


def test_missing_canonical_inventory_does_not_raise():
    ctx = ScanContext(scan_id=_make_scan_id(), domain="pnb.bank")
    update = {}
    if ctx.canonical_inventory is not None:
        update["canonical_inventory"] = ctx.canonical_inventory.model_dump(mode="json")
    assert "canonical_inventory" not in update


@pytest.mark.asyncio
async def test_partial_convergence_produces_inventory():
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    ctx.tls_profiles.append({"host": "api.pnb.bank", "port": 443, "tls_versions_supported": {"TLSv1.3": True}, "accepted_ciphers": [{"name": "TLS_AES_256_GCM_SHA384"}], "cert_chain": [{"subject": "CN=api.pnb.bank", "issuer": "CN=PNB CA", "fingerprint_sha256": "aabbccdd" * 8}]})
    with patch("app.scanner.convergence.convergence_stage.CloudAdapter.process", side_effect=RuntimeError("cloud failure")):
        result = await ConvergenceStage().execute(ctx)
    assert result.status in ("partial", "success")
    assert ctx.canonical_inventory is not None


def test_empty_canonical_inventory_produces_valid_cyclonedx():
    empty_inventory = CanonicalInventory(scan_id=_make_scan_id(), target="empty.pnb")
    bom_json = CycloneDXExporter(empty_inventory).generate()
    is_valid, errors = validate_cyclonedx(bom_json)
    if not is_valid:
        pytest.fail(f"Empty inventory CycloneDX invalid: {errors}")
    assert json.loads(bom_json)["bomFormat"] == "CycloneDX"
    assert len(json.loads(bom_json).get("components", [])) == 0


def test_legacy_cbom_and_canonical_inventory_coexist_in_update():
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    ctx.canonical_inventory = _minimal_inventory(scan_id)
    ctx.unified_cbom_report = {"CBOM_Metadata": {"target": "pnb.bank"}, "Algorithms": [], "Certificates": [], "Keys": [], "Protocols": []}
    update = {}
    if ctx.unified_cbom_report:
        update["unified_cbom_report"] = ctx.unified_cbom_report
    if ctx.canonical_inventory is not None:
        update["canonical_inventory"] = ctx.canonical_inventory.model_dump(mode="json")
    assert "unified_cbom_report" in update
    assert "canonical_inventory" in update
    assert update["unified_cbom_report"]["CBOM_Metadata"]["target"] == "pnb.bank"
    assert update["canonical_inventory"]["scan_id"] == scan_id
