"""
QuantumShield — Convergence Vuln Adapter

Transforms vulnerability findings into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.enums import ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


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
            if not isinstance(vuln, dict) and not hasattr(vuln, "vuln_id") and not hasattr(vuln, "name"):
                msg = f"Skipping malformed vulnerability finding record: invalid type {type(vuln).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            vuln_id = extract_field(vuln, ("vuln_id", "id", "cve_id"), "UNKNOWN-VULN")
            host = extract_field(vuln, "host") or ctx.domain or "unknown"
            conf_raw = extract_field(vuln, "confidence", 1.0)
            try:
                confidence = float(conf_raw) if conf_raw is not None else 1.0
            except (ValueError, TypeError):
                confidence = 1.0

            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="vulnerability_scan",
                target=str(host),
                observed_at=now,
                confidence=confidence,
                value=str(vuln_id)
            )
            evidence.append(ev)
            
            sev_raw = extract_field(vuln, "severity", "info")
            if sev_raw and isinstance(sev_raw, str):
                sev_raw = sev_raw.upper()
                if sev_raw in [r.value for r in RiskLevel]:
                    severity = RiskLevel(sev_raw)
                elif sev_raw in ("INFO", "NONE"):
                    severity = RiskLevel.SAFE
                else:
                    severity = RiskLevel.UNKNOWN
            else:
                severity = RiskLevel.UNKNOWN

            name = extract_field(vuln, "name", str(vuln_id))
            description = extract_field(vuln, "description") or extract_field(vuln, "name", "")
            cve_ids = extract_field(vuln, "cve_ids", []) or []

            cf = CanonicalFinding(
                scan_id=ctx.scan_id,
                finding_type="vulnerability",
                title=str(name),
                description=str(description),
                severity=severity,
                confidence=confidence,
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "vulnerability_id": vuln_id,
                    "host": host,
                    "category": extract_field(vuln, "category"),
                    "affected_component": extract_field(vuln, "affected_component"),
                    "cve_ids": cve_ids,
                    "cvss_score": extract_field(vuln, "cvss_score"),
                    "cvss_vector": extract_field(vuln, "cvss_vector"),
                    "cwe": extract_field(vuln, "cwe"),
                    "quantum_relevance": extract_field(vuln, "quantum_relevance", False)
                }
            )
            
            for cve in cve_ids:
                if cve:
                    cf.references.append({"type": "cve", "id": str(cve)})
                
            findings.append(cf)

        return assets, findings, evidence
