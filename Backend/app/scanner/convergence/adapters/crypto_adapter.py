from datetime import datetime, timezone
from typing import List, Tuple

from app.scanner.convergence.adapters.base_adapter import EngineAdapter, extract_field
from app.scanner.convergence.canonical_models import (
    CanonicalAsset,
    CanonicalEvidence,
    CanonicalFinding,
)
from app.scanner.convergence.enums import AssetType, ObservationStatus, RiskLevel
from app.scanner.pipeline import ScanContext
from app.utils.logger import get_logger

logger = get_logger(__name__)


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
            if not isinstance(crypto, dict) and not hasattr(crypto, "component"):
                msg = f"Skipping malformed crypto finding record: invalid type {type(crypto).__name__}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            component = extract_field(crypto, "component")
            algorithm = extract_field(crypto, "algorithm")
            
            # Skip composite summary score rows emitted by CryptoAnalysisEngine
            if component == "crypto_score":
                continue

            # Check required fields
            if not component or not algorithm:
                msg = f"Skipping malformed crypto finding missing component or algorithm: component={component!r}, algorithm={algorithm!r}"
                logger.warning(msg)
                self.record_error(msg)
                continue

            host = extract_field(crypto, "host") or ctx.domain or ""
            port = extract_field(crypto, "port")
            quantum_risk = str(extract_field(crypto, "quantum_risk", "") or "").lower()
            threat_vector = extract_field(crypto, "threat_vector", "") or ""
            hndl_risk = extract_field(crypto, "hndl_risk", "") or ""
            nist_recommendation = extract_field(crypto, "nist_recommendation", "") or ""
            ev_text = extract_field(crypto, "evidence", "") or ""

            conf_raw = str(extract_field(crypto, "confidence", "high") or "high").lower()
            conf_val = 0.8 if conf_raw == "high" else (0.5 if conf_raw == "medium" else 0.3)

            ev = CanonicalEvidence(
                scan_id=ctx.scan_id,
                source_engine=self.engine_name,
                source_stage=self.engine_stage,
                observation_type="crypto_analysis",
                target=str(host),
                observed_at=now,
                value=f"{component}:{algorithm}",
                confidence=conf_val,
            )
            evidence.append(ev)

            if quantum_risk in ("critical", "high", "medium", "low", "safe"):
                severity = RiskLevel(quantum_risk.upper())
            elif quantum_risk in ("info", "none"):
                severity = RiskLevel.SAFE
            else:
                severity = RiskLevel.UNKNOWN
            
            cf = CanonicalFinding(
                scan_id=ctx.scan_id,
                finding_type="crypto_finding",
                title=f"Crypto Finding in {component}",
                description=f"Algorithm {algorithm} used in {component}.",
                severity=severity,
                confidence=conf_val,
                status=ObservationStatus.OBSERVED,
                source=[self.engine_name],
                evidence_refs=[ev.evidence_id],
                details={
                    "host": host,
                    "port": port,
                    "component": component,
                    "algorithm": algorithm,
                    "quantum_risk": quantum_risk,
                    "threat_vector": threat_vector,
                    "hndl_risk": hndl_risk,
                    "nist_recommendation": nist_recommendation,
                    "evidence": ev_text,
                }
            )
            findings.append(cf)

        return assets, findings, evidence

