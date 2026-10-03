import pytest
from app.scanner.engines.vuln_engine import VulnerabilityEngine
from app.scanner.pipeline import ScanContext

def test_semantic_version_match_exact():
    engine = VulnerabilityEngine()
    assert engine._match_version("1.18.0", "1.18.0") is True
    assert engine._match_version("1.18.1", "1.18.0") is False

def test_semantic_version_match_ranges():
    engine = VulnerabilityEngine()
    assert engine._match_version("1.18.0", "<1.18.5") is True
    assert engine._match_version("1.18.4", "<1.18.5") is True
    assert engine._match_version("1.18.5", "<1.18.5") is False
    assert engine._match_version("1.18.10", "<1.18.5") is False
    
    assert engine._match_version("1.18.5", "<=1.18.5") is True
    assert engine._match_version("1.18.6", "<=1.18.5") is False
    
    assert engine._match_version("1.18.1", ">=1.18.0,<1.18.5") is True
    assert engine._match_version("1.18.0", ">=1.18.0,<1.18.5") is True
    assert engine._match_version("1.18.5", ">=1.18.0,<1.18.5") is False
    assert engine._match_version("1.18.10", ">=1.18.0,<1.18.5") is False

def test_semantic_version_match_wildcard():
    engine = VulnerabilityEngine()
    assert engine._match_version("1.18.0", "*") is True
    assert engine._match_version("unknown", "*") is True

def test_invalid_versions_handled_safely():
    engine = VulnerabilityEngine()
    # Should safely fallback to exact string match or false
    assert engine._match_version("unknown", "<2.0") is False
    assert engine._match_version("latest", "<2.0") is False
    assert engine._match_version("OpenSSH_8", "OpenSSH_8") is True

def test_backport_awareness():
    engine = VulnerabilityEngine()
    ctx = ScanContext(scan_id="test-1")
    ctx.os_fingerprints = [
        {"host": "example.com", "os_family": "linux", "os_version": "ubuntu 20.04"}
    ]
    ctx.tech_fingerprints = [
        {"host": "example.com", "cpe": "cpe:2.3:a:f5:nginx", "version": "1.18.0", "name": "nginx", "evidence_sources": ["banner"]}
    ]
    
    # Mocking cache load for testing
    import json
    from app.scanner.engines.cve_sync import CVESyncManager
    CVESyncManager.sync_from_feed([{
        'cve_id': 'CVE-2021-23017', 
        'cpe_prefix': 'cpe:2.3:a:f5:nginx', 
        'affected_ranges': ['<1.20.1'], 
        'name': 'Nginx Off-By-One', 
        'severity': 'high', 
        'remediation': 'Update Nginx to 1.20.1+'
    }])
    
    findings = engine._correlate_cves(ctx)
    assert len(findings) == 1
    f = findings[0]
    
    # Backport risk check
    assert f["verification_status"] == "POTENTIAL"
    assert f["confidence"] == 0.40
    assert "Enterprise Linux backport risk" in f["evidence"]

def test_strong_evidence_no_backport_discount():
    engine = VulnerabilityEngine()
    ctx = ScanContext(scan_id="test-2")
    ctx.os_fingerprints = [
        {"host": "example.com", "os_family": "windows", "os_version": "windows 10"} # not enterprise linux
    ]
    ctx.tech_fingerprints = [
        {"host": "example.com", "cpe": "cpe:2.3:a:f5:nginx", "version": "1.18.0", "name": "nginx", "evidence_sources": ["package_manager"]} # not banner
    ]
    
    findings = engine._correlate_cves(ctx)
    assert len(findings) == 1
    f = findings[0]
    
    # No backport discount
    assert f["verification_status"] == "CONFIRMED"
    assert f["confidence"] == 0.85
