"""
QuantumShield — Convergence Vuln Adapter

Transforms vulnerability findings into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.enums import ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext


class VulnAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "vuln_engine"

    @property
    def engine_stage(self) -> str:
        return "discovery/vuln"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        for vuln in getattr(ctx, "vuln_findings", []):
            vuln_id = getattr(vuln, "vuln_id", "") or "UNKNOWN-VULN"
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="vulnerability_scan",
                target=getattr(vuln, "host", "unknown"),
                observed_at=now,
                confidence=getattr(vuln, "confidence", 1.0),
                value=vuln_id
            )
            evidence.append(ev)
            
            sev_raw = getattr(vuln, "severity", "info")
            if sev_raw and isinstance(sev_raw, str):
                sev_raw = sev_raw.upper()
                if sev_raw in [r.value for r in RiskLevel]:
                    severity = RiskLevel(sev_raw)
                elif sev_raw == "INFO":
                    severity = RiskLevel.SAFE
                else:
                    severity = RiskLevel.UNKNOWN
            else:
                severity = RiskLevel.UNKNOWN

            cf = CanonicalFinding(
                scan_id=ctx.scan_id,
                finding_type="vulnerability",
                title=getattr(vuln, "name", vuln_id),
                description=getattr(vuln, "name", ""),
                severity=severity,
                confidence=getattr(vuln, "confidence", 1.0),
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "vulnerability_id": vuln_id,
                    "host": getattr(vuln, "host", None),
                    "category": getattr(vuln, "category", None),
                    "affected_component": getattr(vuln, "affected_component", None),
                    "cve_ids": getattr(vuln, "cve_ids", []),
                    "cvss_score": getattr(vuln, "cvss_score", None),
                    "cvss_vector": getattr(vuln, "cvss_vector", None),
                    "cwe": getattr(vuln, "cwe", None),
                    "quantum_relevance": getattr(vuln, "quantum_relevance", False)
                }
            )
            
            for cve in getattr(vuln, "cve_ids", []):
                cf.references.append({"type": "cve", "id": cve})
                
            findings.append(cf)

        return assets, findings, evidence
