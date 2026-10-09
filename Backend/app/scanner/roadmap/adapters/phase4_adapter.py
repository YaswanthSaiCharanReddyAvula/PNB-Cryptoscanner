"""
Phase 4 Adapter

Bridges the gap between the QuantumRiskEngine (Phase 4) and the Roadmap Engine.
Provides authoritative quantum risk, Mosca urgency, and HNDL exposure.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel

from app.scanner.quantum.models import QuantumRiskAssessment, AssetQuantumRiskSummary


class NormalizedQuantumContext(BaseModel):
    quantum_risk_score: float = 0.0
    algorithmic_risk: float = 0.0
    hndl_exposure: float = 0.0
    mosca_urgency_score: float = 0.0
    mosca_status: str = "UNKNOWN"
    migration_priority: str = "UNKNOWN"
    confidence: float = 1.0


class Phase4Context:
    def __init__(self, assessments: List[QuantumRiskAssessment], summaries: List[AssetQuantumRiskSummary]):
        self._assessments_by_asset: Dict[str, List[QuantumRiskAssessment]] = {}
        self._summary_by_asset: Dict[str, AssetQuantumRiskSummary] = {}
        
        for a in assessments:
            self._assessments_by_asset.setdefault(a.asset_id, []).append(a)
            
        for s in summaries:
            self._summary_by_asset[s.asset_id] = s
            
    def get_quantum_context_for_asset(self, asset_id: str) -> NormalizedQuantumContext:
        """Returns the aggregated quantum risk for the asset."""
        summary = self._summary_by_asset.get(asset_id)
        if not summary:
            return NormalizedQuantumContext()
            
        # Convert Mosca status to a scalar score for priority calculation
        mosca_score = 0.0
        if summary.mosca.status == "CRITICAL_URGENCY":
            mosca_score = 100.0
        elif summary.mosca.status == "MIGRATION_REQUIRED":
            mosca_score = 80.0
        elif summary.mosca.status == "BORDERLINE":
            mosca_score = 50.0
            
        return NormalizedQuantumContext(
            quantum_risk_score=summary.quantum_risk_score,
            algorithmic_risk=summary.quantum_risk_score, # Summary uses overall risk as proxy
            hndl_exposure=summary.hndl.exposure,
            mosca_urgency_score=mosca_score,
            mosca_status=summary.mosca.status,
            migration_priority=summary.migration_priority,
            confidence=summary.confidence
        )

    def get_highest_quantum_context(self, asset_ids: List[str]) -> NormalizedQuantumContext:
        """Returns the highest risk context among a list of assets (e.g. for a finding affecting multiple assets)."""
        best_ctx = NormalizedQuantumContext()
        
        for asset_id in asset_ids:
            ctx = self.get_quantum_context_for_asset(asset_id)
            if ctx.quantum_risk_score > best_ctx.quantum_risk_score:
                best_ctx.quantum_risk_score = ctx.quantum_risk_score
            if ctx.hndl_exposure > best_ctx.hndl_exposure:
                best_ctx.hndl_exposure = ctx.hndl_exposure
            if ctx.mosca_urgency_score > best_ctx.mosca_urgency_score:
                best_ctx.mosca_urgency_score = ctx.mosca_urgency_score
                best_ctx.mosca_status = ctx.mosca_status
            if ctx.confidence < best_ctx.confidence: # take lowest confidence
                best_ctx.confidence = ctx.confidence
                
        return best_ctx
