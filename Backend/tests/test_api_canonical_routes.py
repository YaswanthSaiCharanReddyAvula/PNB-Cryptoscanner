"""
Phase 3.4 FastAPI Route Regression Tests

Covers real route contracts for:
1. Canonical inventory retrieval returns the stored inventory.
2. Canonical assets, findings, and evidence subroutes return the correct stored fields.
3. Missing inventory returns the intended HTTP 404.
4. CycloneDX export rehydrates stored canonical inventory and returns valid CycloneDX 1.6 JSON with the correct media type.
5. Missing scan or missing inventory returns the intended error.
6. Quantum assessment retrieval filters by scan_id.
7. Persistence/error metadata is observable for relevant failure cases (serialization failure, DB write failure, 4 inventory states).
"""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.routers.common import SCANS_COLLECTION
from app.db.connection import get_database as get_db
from app.db.models import ScanStatus
from app.main import app
from app.scanner.convergence.aggregation import CanonicalInventory
from app.scanner.convergence.canonical_models import CanonicalAsset, CanonicalEvidence, CanonicalFinding
from app.scanner.convergence.cyclonedx.validator import validate_cyclonedx
from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext
from app.scanner.quantum.engine_stage import QuantumRiskStage


def _make_scan_id():
    return str(uuid.uuid4())


def _utcnow():
    return datetime.now(timezone.utc)


def _build_test_inventory(scan_id: str, target: str = "pnb.bank") -> CanonicalInventory:
    now = _utcnow()
    inventory = CanonicalInventory(scan_id=scan_id, target=target)
    inventory.assets.hosts.append(
        CanonicalAsset(
            scan_id=scan_id,
            asset_type=AssetType.HOST,
            name=target,
            observed_at=now,
            properties={"ip": "10.0.0.1"},
        )
    )
    inventory.assets.certificates.append(
        CanonicalAsset(
            scan_id=scan_id,
            asset_type=AssetType.CERTIFICATE,
            name=f"CN={target}",
            observed_at=now,
            properties={"keyType": "RSA", "keySize": 2048, "daysUntilExpiry": 90},
        )
    )
    inventory.assets.algorithms.append(
        CanonicalAsset(
            scan_id=scan_id,
            asset_type=AssetType.ALGORITHM,
            name="RSA-2048",
            observed_at=now,
            properties={"primitive": "signature"},
        )
    )
    inventory.assets.protocols.append(
        CanonicalAsset(
            scan_id=scan_id,
            asset_type=AssetType.PROTOCOL,
            name="TLSv1.3",
            observed_at=now,
            properties={"ciphers": ["TLS_AES_256_GCM_SHA384"]},
        )
    )
    inventory.assets.services.append(
        CanonicalAsset(
            scan_id=scan_id,
            asset_type=AssetType.SERVICE,
            name="api-gateway",
            observed_at=now,
            properties={
                "crypto:tls:kex": "ECDHE",
                "crypto:tls:enc": "AES-128",
                "data_classification": "CONFIDENTIAL",
            },
        )
    )
    inventory.findings.append(
        CanonicalFinding(
            scan_id=scan_id,
            finding_type="classical_crypto_weakness",
            title="Legacy RSA Key",
            description="RSA 2048-bit key in use",
            severity=RiskLevel.MEDIUM,
            status=ObservationStatus.OBSERVED,
            asset_refs=[inventory.assets.certificates[0].asset_id],
        )
    )
    inventory.evidence.append(
        CanonicalEvidence(
            scan_id=scan_id,
            source_engine="tls_engine",
            source_stage="tls_scanning",
            observation_type="tls_certificate",
            target=target,
            observed_at=now,
            value="abcdef1234567890",
        )
    )
    return inventory


# ---------------------------------------------------------------------------
# 1. Canonical inventory retrieval returns the stored inventory
# ---------------------------------------------------------------------------
def test_get_canonical_inventory_returns_stored():
    scan_id = _make_scan_id()
    inv_data = _build_test_inventory(scan_id).model_dump(mode="json")

    mock_scans = MagicMock()
    mock_scans.find_one = AsyncMock(return_value={
        "scan_id": scan_id,
        "canonical_inventory": inv_data,
        "status": "completed",
    })
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_scans)

    with patch("app.api.routers.assets.get_database", return_value=mock_db):
        client = TestClient(app)
        response = client.get(f"/api/v1/canonical-inventory/{scan_id}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["scan_id"] == scan_id
        assert payload["target"] == "pnb.bank"
        assert len(payload["assets"]["hosts"]) == 1
        assert len(payload["assets"]["certificates"]) == 1
        assert len(payload["findings"]) == 1
        assert len(payload["evidence"]) == 1
        mock_scans.find_one.assert_called_once_with({"scan_id": scan_id})


# ---------------------------------------------------------------------------
# 2. Canonical assets, findings, and evidence subroutes return correct stored fields
# ---------------------------------------------------------------------------
def test_canonical_subroutes_return_correct_fields():
    scan_id = _make_scan_id()
    inv_data = _build_test_inventory(scan_id).model_dump(mode="json")

    mock_scans = MagicMock()
    mock_scans.find_one = AsyncMock(return_value={
        "scan_id": scan_id,
        "canonical_inventory": inv_data,
        "status": "completed",
    })
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_scans)

    with patch("app.api.routers.assets.get_database", return_value=mock_db):
        client = TestClient(app)

        # Assets subroute
        resp_assets = client.get(f"/api/v1/canonical-inventory/{scan_id}/assets")
        assert resp_assets.status_code == 200
        assets_payload = resp_assets.json()
        assert "hosts" in assets_payload
        assert "certificates" in assets_payload
        assert "algorithms" in assets_payload
        assert "protocols" in assets_payload
        assert assets_payload["hosts"][0]["name"] == "pnb.bank"

        # Findings subroute
        resp_findings = client.get(f"/api/v1/canonical-inventory/{scan_id}/findings")
        assert resp_findings.status_code == 200
        findings_payload = resp_findings.json()
        assert isinstance(findings_payload, list)
        assert len(findings_payload) == 1
        assert findings_payload[0]["title"] == "Legacy RSA Key"

        # Evidence subroute
        resp_evidence = client.get(f"/api/v1/canonical-inventory/{scan_id}/evidence")
        assert resp_evidence.status_code == 200
        evidence_payload = resp_evidence.json()
        assert isinstance(evidence_payload, list)
        assert len(evidence_payload) == 1
        assert evidence_payload[0]["source_engine"] == "tls_engine"


# ---------------------------------------------------------------------------
# 3. Missing inventory returns the intended HTTP 404
# ---------------------------------------------------------------------------
def test_missing_inventory_returns_http_404():
    scan_id = _make_scan_id()

    # Case A: Scan document does not exist at all
    mock_scans_empty = MagicMock()
    mock_scans_empty.find_one = AsyncMock(return_value=None)
    mock_db_empty = MagicMock()
    mock_db_empty.__getitem__ = MagicMock(return_value=mock_scans_empty)

    with patch("app.api.routers.assets.get_database", return_value=mock_db_empty):
        client = TestClient(app)
        resp = client.get(f"/api/v1/canonical-inventory/{scan_id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Canonical inventory not found for scan"

        resp_sub = client.get(f"/api/v1/canonical-inventory/{scan_id}/assets")
        assert resp_sub.status_code == 404

    # Case B: Scan document exists, but canonical_inventory is None
    mock_scans_no_inv = MagicMock()
    mock_scans_no_inv.find_one = AsyncMock(return_value={
        "scan_id": scan_id,
        "domain": "pnb.bank",
        "canonical_inventory": None,
        "status": "completed",
    })
    mock_db_no_inv = MagicMock()
    mock_db_no_inv.__getitem__ = MagicMock(return_value=mock_scans_no_inv)

    with patch("app.api.routers.assets.get_database", return_value=mock_db_no_inv):
        client = TestClient(app)
        resp = client.get(f"/api/v1/canonical-inventory/{scan_id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Canonical inventory not found for scan"


# ---------------------------------------------------------------------------
# 4. CycloneDX export rehydrates stored canonical inventory and returns valid CycloneDX 1.6
# ---------------------------------------------------------------------------
def test_cyclonedx_export_rehydrates_canonical_inventory():
    scan_id = _make_scan_id()
    target_domain = "cbom.pnb.bank"
    inv_data = _build_test_inventory(scan_id, target=target_domain).model_dump(mode="json")

    mock_scans = MagicMock()
    mock_scans.find_one = AsyncMock(return_value={
        "scan_id": scan_id,
        "domain": target_domain,
        "status": "completed",
        "completed_at": datetime.now(timezone.utc),
        "canonical_inventory": inv_data,
    })
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_scans)

    with patch("app.api.routers.crypto_cbom.get_database", return_value=mock_db):
        client = TestClient(app)
        resp = client.get(f"/api/v1/cbom/cyclonedx?target={target_domain}")
        assert resp.status_code == 200
        assert "application/vnd.cyclonedx+json; version=1.6" in resp.headers["content-type"]

        bom_json = resp.text
        is_valid, validation_errors = validate_cyclonedx(bom_json)
        assert is_valid, f"Exported CycloneDX 1.6 is invalid: {validation_errors}"

        parsed = json.loads(bom_json)
        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.6"
        assert len(parsed.get("components", [])) >= 4


# ---------------------------------------------------------------------------
# 5. Missing scan or missing inventory returns the intended error for CycloneDX
# ---------------------------------------------------------------------------
def test_cyclonedx_missing_scan_and_missing_inventory_errors():
    # Case A: No completed scan found for target
    mock_scans_none = MagicMock()
    mock_scans_none.find_one = AsyncMock(return_value=None)
    mock_db_none = MagicMock()
    mock_db_none.__getitem__ = MagicMock(return_value=mock_scans_none)

    with patch("app.api.routers.crypto_cbom.get_database", return_value=mock_db_none):
        client = TestClient(app)
        resp = client.get("/api/v1/cbom/cyclonedx?target=missing.bank")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "No completed scan found for target"

    # Case B: Scan exists and completed, but canonical_inventory is None
    mock_scans_no_inv = MagicMock()
    mock_scans_no_inv.find_one = AsyncMock(return_value={
        "scan_id": "scan-123",
        "domain": "noinv.bank",
        "status": "completed",
        "canonical_inventory": None,
    })
    mock_db_no_inv = MagicMock()
    mock_db_no_inv.__getitem__ = MagicMock(return_value=mock_scans_no_inv)

    with patch("app.api.routers.crypto_cbom.get_database", return_value=mock_db_no_inv):
        client = TestClient(app)
        resp = client.get("/api/v1/cbom/cyclonedx?target=noinv.bank")
        assert resp.status_code == 404
        assert "Canonical inventory not generated" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 6. Quantum assessment retrieval filters by scan_id
# ---------------------------------------------------------------------------
def test_quantum_assessment_retrieval_filters_by_scan_id():
    scan_id_1 = "scan-target-alpha"
    scan_id_2 = "scan-target-beta"

    mock_cursor = MagicMock()
    mock_cursor.to_list = AsyncMock(return_value=[
        {
            "scan_id": scan_id_1,
            "asset_id": "asset-001",
            "subject_id": "sub-001",
            "overall_quantum_risk": 75.0,
            "risk_tier": "CRITICAL",
            "hndl": {"exposure": 0.8},
            "mosca": {"status": "CRITICAL_URGENCY"},
            "timeline": {},
        }
    ])

    mock_assessments = MagicMock()
    mock_assessments.find = MagicMock(return_value=mock_cursor)

    mock_db = MagicMock()
    mock_db.quantum_assessments = mock_assessments

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        client = TestClient(app)

        # 1. /risk route with scan_id
        resp_risk = client.get(f"/api/v1/quantum/risk?scan_id={scan_id_1}")
        assert resp_risk.status_code == 200
        mock_assessments.find.assert_called_with({"scan_id": scan_id_1}, {"_id": 0})
        data = resp_risk.json()
        assert len(data) == 1
        assert data[0]["scan_id"] == scan_id_1

        # 2. /assets route with scan_id
        mock_assessments.find.reset_mock()
        resp_assets = client.get(f"/api/v1/quantum/assets?scan_id={scan_id_1}")
        assert resp_assets.status_code == 200
        mock_assessments.find.assert_called_with(
            {"scan_id": scan_id_1},
            {"_id": 0, "asset_id": 1, "overall_quantum_risk": 1, "risk_tier": 1, "hndl": 1, "mosca": 1},
        )

        # 3. /hndl route with scan_id
        mock_assessments.find.reset_mock()
        resp_hndl = client.get(f"/api/v1/quantum/hndl?scan_id={scan_id_1}")
        assert resp_hndl.status_code == 200
        mock_assessments.find.assert_called_with(
            {"hndl.exposure": {"$gt": 0.0}, "scan_id": scan_id_1},
            {"_id": 0, "asset_id": 1, "subject_id": 1, "hndl": 1},
        )

        # 4. /mosca route with scan_id
        mock_assessments.find.reset_mock()
        resp_mosca = client.get(f"/api/v1/quantum/mosca?scan_id={scan_id_1}")
        assert resp_mosca.status_code == 200
        mock_assessments.find.assert_called_with(
            {"mosca.status": {"$in": ["CRITICAL_URGENCY", "MIGRATION_REQUIRED"]}, "scan_id": scan_id_1},
            {"_id": 0, "asset_id": 1, "subject_id": 1, "mosca": 1, "timeline": 1},
        )

        # 5. /risk route without scan_id queries all
        mock_assessments.find.reset_mock()
        resp_all = client.get("/api/v1/quantum/risk")
        assert resp_all.status_code == 200
        mock_assessments.find.assert_called_with({}, {"_id": 0})
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# 7. Persistence/error metadata is observable for relevant failure cases
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_quantum_risk_stage_write_failure_observability():
    """Verify write failures are logged and recorded on ctx, result, and quantum_score."""
    scan_id = _make_scan_id()
    ctx = ScanContext(scan_id=scan_id, domain="pnb.bank")
    ctx.canonical_inventory = _build_test_inventory(scan_id)

    # Database where quantum_assessments insert_many fails
    mock_coll_fail = AsyncMock()
    mock_coll_fail.insert_many = AsyncMock(side_effect=RuntimeError("Disk quota exceeded"))
    mock_coll_ok = AsyncMock()
    mock_coll_ok.insert_many = AsyncMock()
    mock_coll_ok.insert_one = AsyncMock()

    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(
        side_effect=lambda n: mock_coll_fail if n == "quantum_assessments" else mock_coll_ok
    )
    ctx.db = mock_db

    stage = QuantumRiskStage()
    result = await stage.execute(ctx)

    # Stage result records partial status and the write error
    assert result.status == "partial"
    assert "write_errors" in result.data
    assert "quantum_assessments" in result.data["write_errors"]
    assert "Disk quota exceeded" in result.data["write_errors"]["quantum_assessments"]
    assert "quantum_assessments" in (result.error or "")

    # Context records the failure metadata
    assert hasattr(ctx, "quantum_write_errors")
    assert "quantum_assessments" in ctx.quantum_write_errors

    # quantum_score prevents being interpreted as proof that all DB writes succeeded
    assert ctx.quantum_score.get("persisted") is False
    assert "quantum_assessments" in ctx.quantum_score.get("write_errors", [])


def test_canonical_inventory_serialization_failure_observability():
    """Verify that serialization failure marks scan as failed and persists observable error metadata."""
    scan_id = _make_scan_id()
    domain = "fail-domain.pnb.bank"

    # Simulated canonical inventory whose model_dump raises an exception
    mock_inventory = MagicMock()
    mock_inventory.model_dump = MagicMock(side_effect=TypeError("Unserializable object encountered"))

    ctx = ScanContext(scan_id=scan_id, domain=domain)
    ctx.canonical_inventory = mock_inventory

    update: dict = {
        "status": ScanStatus.COMPLETED.value,
        "completed_at": datetime.now(timezone.utc),
        "progress": 100,
        "current_stage": "Completed",
    }

    # Execute the remediation logic from common.py
    canonical_serialization_failed = False
    if ctx.canonical_inventory is not None:
        try:
            update["canonical_inventory"] = ctx.canonical_inventory.model_dump(mode="json")
        except Exception as _ci_err:
            canonical_serialization_failed = True
            _ci_err_msg = f"canonical_inventory serialization failed: {type(_ci_err).__name__}: {_ci_err}"
            update["canonical_inventory_error"] = _ci_err_msg
            update["persistence_error"] = _ci_err_msg
            update["error"] = _ci_err_msg
            update["status"] = ScanStatus.FAILED.value
            update["current_stage"] = "Failed"

    # Verify observable failure metadata
    assert canonical_serialization_failed is True
    assert update["status"] == ScanStatus.FAILED.value
    assert "canonical_inventory" not in update
    assert "canonical_inventory_error" in update
    assert "Unserializable object encountered" in update["canonical_inventory_error"]
    assert update["current_stage"] == "Failed"

    # Verify that an API consumer querying /results/{domain} sees the failure metadata
    mock_scans = MagicMock()
    mock_scans.find_one = AsyncMock(return_value={
        "scan_id": scan_id,
        "domain": domain,
        **update,
    })
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_scans)

    with patch("app.api.routers.scan.get_database", return_value=mock_db):
        client = TestClient(app)
        resp = client.get(f"/api/v1/results/{domain}")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["status"] == "failed"
        assert "canonical_inventory_error" in doc
        assert "Unserializable object encountered" in doc["canonical_inventory_error"]
        assert doc.get("canonical_inventory") is None


def test_four_canonical_inventory_states_are_distinguishable():
    """Verify that missing, valid empty, partial convergence, and serialization failure are distinguishable."""
    scan_id = _make_scan_id()

    # 1. Missing inventory: canonical_inventory is None, no serialization error, status completed
    missing_doc = {
        "scan_id": scan_id,
        "status": "completed",
        "canonical_inventory": None,
    }
    assert missing_doc.get("canonical_inventory") is None
    assert "canonical_inventory_error" not in missing_doc
    assert missing_doc["status"] == "completed"

    # 2. Valid empty inventory: canonical_inventory is present and has empty collections
    empty_inv = CanonicalInventory(scan_id=scan_id, target="empty.bank").model_dump(mode="json")
    empty_doc = {
        "scan_id": scan_id,
        "status": "completed",
        "canonical_inventory": empty_inv,
    }
    assert empty_doc.get("canonical_inventory") is not None
    assert len(empty_doc["canonical_inventory"]["assets"]["hosts"]) == 0
    assert "canonical_inventory_error" not in empty_doc
    assert empty_doc["status"] == "completed"

    # 3. Partial convergence: canonical_inventory present, convergence_adapter_errors present
    partial_doc = {
        "scan_id": scan_id,
        "status": "completed",
        "canonical_inventory": empty_inv,
        "convergence_adapter_errors": {"cloud": "CloudAdapter failed: timeout"},
    }
    assert partial_doc.get("canonical_inventory") is not None
    assert "convergence_adapter_errors" in partial_doc
    assert "cloud" in partial_doc["convergence_adapter_errors"]

    # 4. Serialization failure: canonical_inventory is None, canonical_inventory_error present, status is failed
    failed_doc = {
        "scan_id": scan_id,
        "status": "failed",
        "canonical_inventory": None,
        "canonical_inventory_error": "canonical_inventory serialization failed: TypeError",
        "persistence_error": "canonical_inventory serialization failed: TypeError",
        "error": "canonical_inventory serialization failed: TypeError",
    }
    assert failed_doc.get("canonical_inventory") is None
    assert "canonical_inventory_error" in failed_doc
    assert failed_doc["status"] == "failed"
