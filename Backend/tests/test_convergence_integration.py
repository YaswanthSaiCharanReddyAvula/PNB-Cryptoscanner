"""
Tests for Convergence Engine and CycloneDX generation.
"""

import pytest
import uuid
import json
from datetime import datetime, timezone

from app.scanner.pipeline import ScanContext
from app.scanner.convergence.convergence_stage import ConvergenceStage
from app.scanner.convergence.cyclonedx.exporter import CycloneDXExporter
from app.scanner.convergence.cyclonedx.validator import validate_cyclonedx
from app.scanner.models import TLSProfile, CipherDetail, CertificateDetail
from app.scanner.sca.models.package import PackageIdentity, Ecosystem, SCAFindingV2


@pytest.mark.asyncio
async def test_convergence_and_cyclonedx():
    ctx = ScanContext(scan_id=str(uuid.uuid4()), domain="example.com")
    
    # Add some mock TLS data
    cipher = CipherDetail(name="TLS_AES_256_GCM_SHA384", primitive="symmetric")
    cert = CertificateDetail(
        subject="CN=example.com",
        issuer="CN=Let's Encrypt",
        valid_from="2023-01-01T00:00:00Z",
        valid_to="2024-01-01T00:00:00Z",
        fingerprint_sha256="deadbeef" * 8
    )
    
    profile = TLSProfile(
        host="example.com",
        port=443,
        accepted_ciphers=[cipher],
        cert_chain=[cert],
        tls_versions_supported={"TLSv1.2": True, "TLSv1.3": True}
    )
    ctx.tls_profiles.append(profile)
    
    # Add some mock SCA data
    pkg = PackageIdentity(ecosystem=Ecosystem.PYPI, name="requests", version="2.31.0")
    sca_finding = SCAFindingV2(
        finding_id=str(uuid.uuid4()),
        package=pkg,
        resolved_version="2.31.0",
        vulnerability_id="CVE-2023-XXXX",
        manifest_file="requirements.txt"
    )
    ctx.package_findings.append(sca_finding)
    ctx.sca_findings.append(sca_finding)
    
    # Run convergence
    stage = ConvergenceStage()
    result = await stage.execute(ctx)
    
    assert result.status == "success"
    assert ctx.canonical_inventory is not None
    
    estate = ctx.canonical_inventory
    assert len(estate.assets.services) == 1
    assert len(estate.assets.certificates) == 1
    assert len(estate.assets.protocols) == 2
    assert len(estate.assets.algorithms) == 1
    assert len(estate.assets.packages) == 1
    
    # Export to CycloneDX
    exporter = CycloneDXExporter(estate)
    cdx_json = exporter.generate()
    
    assert cdx_json is not None
    
    # Validate output
    is_valid, errors = validate_cyclonedx(cdx_json)
    
    # Print errors for debugging if any
    if not is_valid:
        print("CycloneDX Validation Errors:", errors)
        
    assert is_valid is True
    
    # Parse and check structure
    parsed = json.loads(cdx_json)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert "metadata" in parsed
    assert "components" in parsed
