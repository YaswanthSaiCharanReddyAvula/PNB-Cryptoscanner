"""
QuantumShield — Convergence Crypto Adapter

Transforms general cryptographic findings into canonical models.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext


class CryptoAdapter(EngineAdapter):
    @property
    def engine_name(self) -> str:
        return "crypto_analysis"

    @property
    def engine_stage(self) -> str:
        return "analysis/crypto"

    def process(self, ctx: ScanContext) -> Tuple[List[CanonicalAsset], List[CanonicalFinding], List[CanonicalEvidence]]:
        assets: List[CanonicalAsset] = []
        findings: List[CanonicalFinding] = []
        evidence: List[CanonicalEvidence] = []
        
        now = datetime.now(timezone.utc)

        for crypto in getattr(ctx, "crypto_findings", []):
            host = getattr(crypto, "host", "unknown")
            component = getattr(crypto, "component", "unknown_component")
            algorithm = getattr(crypto, "algorithm", "unknown_algorithm")
            
            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="crypto_analysis",
                target=host,
                observed_at=now,
                value=f"{component}:{algorithm}",
                confidence=0.8 if getattr(crypto, "confidence", "high").lower() == "high" else 0.5
            )
            evidence.append(ev)
            
            cf = CanonicalFinding(
                scan_id=ctx.scan_id,
                finding_type="crypto_finding",
                title=f"Crypto Finding in {component}",
                description=f"Algorithm {algorithm} used in {component}.",
                severity=RiskLevel.UNKNOWN,  # Let risk engine determine severity based on hndl_risk / quantum_risk
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "host": host,
                    "component": component,
                    "algorithm": algorithm,
                    "quantum_risk": getattr(crypto, "quantum_risk", ""),
                    "threat_vector": getattr(crypto, "threat_vector", ""),
                    "hndl_risk": getattr(crypto, "hndl_risk", ""),
                    "nist_recommendation": getattr(crypto, "nist_recommendation", "")
                }
            )
            findings.append(cf)

        return assets, findings, evidence
