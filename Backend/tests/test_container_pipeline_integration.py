"""
QuantumShield — Container Pipeline & CBOM Integration Tests
Tests:
  - End-to-end container image archive inspection with InspectionCoordinator
  - Stage 15 HostScannerEngine execution with ScanContext
  - Track B + Track C CBOM Unification with real cryptographic evidence
  - CBOM Report validation (Certificates, Keys, Algorithms)
"""

import io
import json
import os
import tarfile
import tempfile
import pytest
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanner.container.coordinator import InspectionCoordinator
from app.scanner.container.models import InspectionTarget, TargetType, TargetAuthorization
from app.scanner.engines.host_scanner import HostScannerEngine
from app.scanner.engines.cbom_unification import CBOMUnificationEngine
from app.scanner.pipeline import ScanContext


@pytest.fixture
def sample_container_tar(tmp_path):
    """
    Creates a mock Docker image archive (.tar) containing:
      - manifest.json
      - config.json
      - Layer 1 (base): /etc/ssl/certs/old.crt, /app/package.json
      - Layer 2 (patch): whiteout for old.crt (.wh.old.crt), new key /app/server.key and cert /app/server.crt
    """
    # 1. Generate RSA key and cert
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "container-api.internal"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(12345678)
        .not_valid_before(now)
        .not_valid_after(now + datetime.resolution * 365)
        .sign(priv, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Layer 1 tar
    layer1_path = tmp_path / "layer1.tar"
    with tarfile.open(layer1_path, "w") as tar:
        # Old cert
        ti_old = tarfile.TarInfo("etc/ssl/certs/old.crt")
        ti_old.size = len(cert_pem)
        tar.addfile(ti_old, io.BytesIO(cert_pem))

        # Node package.json with crypto library
        pkg_json = json.dumps({
            "name": "payment-api",
            "version": "1.0.0",
            "dependencies": {
                "jsonwebtoken": "9.0.0",
                "express": "4.18.2"
            }
        }).encode("utf-8")
        ti_pkg = tarfile.TarInfo("app/package.json")
        ti_pkg.size = len(pkg_json)
        tar.addfile(ti_pkg, io.BytesIO(pkg_json))

    # Layer 2 tar
    layer2_path = tmp_path / "layer2.tar"
    with tarfile.open(layer2_path, "w") as tar:
        # Whiteout for old.crt
        ti_wh = tarfile.TarInfo("etc/ssl/certs/.wh.old.crt")
        ti_wh.size = 0
        tar.addfile(ti_wh, io.BytesIO(b""))

        # New cert & key
        ti_new_crt = tarfile.TarInfo("app/server.crt")
        ti_new_crt.size = len(cert_pem)
        tar.addfile(ti_new_crt, io.BytesIO(cert_pem))

        ti_new_key = tarfile.TarInfo("app/server.key")
        ti_new_key.size = len(priv_pem)
        tar.addfile(ti_new_key, io.BytesIO(priv_pem))

    # Image config JSON
    config_dict = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-10-05T00:00:00Z",
        "config": {
            "Entrypoint": ["/app/entrypoint.sh"],
            "Env": [
                "PATH=/usr/local/bin:/usr/bin",
                "SSL_CERT_FILE=/app/server.crt",
                "TLS_KEY=secret_unencrypted_key_token",
            ],
            "User": "10001",
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:diff1", "sha256:diff2"],
        }
    }
    config_bytes = json.dumps(config_dict).encode("utf-8")

    # Manifest JSON
    manifest = [{
        "Config": "config.json",
        "RepoTags": ["payment-api:1.0.0"],
        "Layers": ["layer1.tar", "layer2.tar"]
    }]
    manifest_bytes = json.dumps(manifest).encode("utf-8")

    # Build outer container archive
    archive_path = tmp_path / "payment-api.tar"
    with tarfile.open(archive_path, "w") as tar:
        ti_man = tarfile.TarInfo("manifest.json")
        ti_man.size = len(manifest_bytes)
        tar.addfile(ti_man, io.BytesIO(manifest_bytes))

        ti_cfg = tarfile.TarInfo("config.json")
        ti_cfg.size = len(config_bytes)
        tar.addfile(ti_cfg, io.BytesIO(config_bytes))

        tar.add(str(layer1_path), arcname="layer1.tar")
        tar.add(str(layer2_path), arcname="layer2.tar")

    return str(archive_path)


class TestContainerPipelineAndCBOM:
    """Test full integration from container inspection into CBOM generation."""

    def test_inspection_coordinator_on_container_archive(self, sample_container_tar):
        target = InspectionTarget(
            target_id="test-payment-container",
            target_type=TargetType.CONTAINER_ARCHIVE,
            source_uri=sample_container_tar,
            scope_root=sample_container_tar,
            authorization=TargetAuthorization(
                is_authorized=True,
                scope_root=sample_container_tar,
            ),
        )

        coordinator = InspectionCoordinator()
        result = coordinator.inspect_target(target)

        assert result.scan_metadata.get("status") == "completed"
        assert result.target_metadata.get("image_metadata") is not None
        assert result.target_metadata["image_metadata"]["repository"] == "payment-api"

        # Verify old.crt was deleted by whiteout in Layer 2!
        obs_paths = [o.file_path.replace("\\", "/") for o in result.crypto_observations]
        assert not any("old.crt" in p for p in obs_paths), "Whiteout failed: deleted cert should not be present in final observations"

        # Verify server.crt and server.key were discovered
        assert any("server.crt" in p for p in obs_paths)
        assert any("server.key" in p for p in obs_paths)

        # Verify package discovery (jsonwebtoken)
        pkg_names = [p.name for p in result.packages_discovered]
        assert "jsonwebtoken" in pkg_names

        # Verify cryptographic correlation between server.key and server.crt
        corrs = result.target_metadata.get("key_cert_correlations", [])
        assert len(corrs) >= 1
        assert corrs[0]["correlation_type"] == "public_key_cryptographic_match"

    @pytest.mark.asyncio
    async def test_host_scanner_stage_execution(self, sample_container_tar):
        """Test Track B Stage 15 execution within ScanContext."""
        ctx = ScanContext(
            scan_id="test-scan-container-1",
            domain="internal.payment.local",
            options={
                "container_images": [sample_container_tar],
            },
        )

        stage = HostScannerEngine()
        result = await stage.execute(ctx)

        assert result.status == "completed"
        assert len(result.data["crypto_observations"]) > 0
        assert len(result.data["internal_certificates"]) > 0
        assert len(result.data["container_findings"]) > 0
        assert len(result.data["package_findings"]) > 0

    @pytest.mark.asyncio
    async def test_cbom_unification_from_container_findings(self, sample_container_tar):
        """Test Stage 15 (HostScanner) -> Stage 16 (CBOMUnification) pipeline integration."""
        ctx = ScanContext(
            scan_id="test-cbom-unify-1",
            domain="internal.payment.local",
            options={
                "container_images": [sample_container_tar],
            },
        )

        # 1. Run Host / Container Scanner Stage
        host_stage = HostScannerEngine()
        host_res = await host_stage.execute(ctx)

        # Merge results into ctx (as PipelineManager._merge does)
        ctx.crypto_observations = host_res.data["crypto_observations"]
        ctx.internal_certificates = host_res.data["internal_certificates"]
        ctx.host_config_findings = host_res.data["host_config_findings"]
        ctx.container_findings = host_res.data["container_findings"]
        ctx.package_findings = host_res.data["package_findings"]

        # 2. Run CBOM Unification Stage
        cbom_stage = CBOMUnificationEngine()
        cbom_res = await cbom_stage.execute(ctx)

        assert cbom_res.status == "completed"
        cbom_report = cbom_res.data["unified_cbom_report"]
        assert cbom_report is not None

        # Verify CBOM Certificates contain the container cert
        certs = cbom_report.get("Certificates", [])
        assert len(certs) >= 1
        cert_names = [c["Name"] for c in certs]
        assert "container-api.internal" in cert_names

        # Verify CBOM Keys contain the RSA key from container
        keys = cbom_report.get("Keys", [])
        assert len(keys) >= 1
        key_sources = [k["Source"] for k in keys]
        assert any("Container" in s or "server" in s for s in key_sources)

        # Verify CBOM Algorithms contain RSA
        algos = cbom_report.get("Algorithms", [])
        algo_names = [a["Name"] for a in algos]
        assert any("RSA" in a for a in algo_names)
