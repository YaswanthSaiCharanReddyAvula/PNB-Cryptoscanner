from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.scanner.roadmap.adapters.phase3_adapter import CanonicalFinding, AssetContext
from app.scanner.roadmap.context_resolver import ContextResolver
from app.scanner.roadmap.eligibility import CandidateEligibilityEngine
from app.scanner.roadmap.trade_off import TradeOffMatrix, DecisionPolicy

class RecommendationModel(BaseModel):
    recommendation_id: str
    asset_ids: List[str]
    finding_ids: List[str]
    cryptographic_role: str
    observed_configuration: str
    recommended_candidate: Optional[str] = None
    alternative_candidates: List[str] = Field(default_factory=list)
    rejected_candidates: List[dict] = Field(default_factory=list)
    trade_off_profile: dict = Field(default_factory=dict)
    candidate_scores: dict = Field(default_factory=dict)
    eligibility_results: dict = Field(default_factory=dict)
    required_prerequisites: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    confidence: float = 0.5
    evidence: List[str] = Field(default_factory=list)
    standards_references: List[str] = Field(default_factory=list)
    catalogue_version: str = "1.0.0"
    decision_policy_version: str = "1.0.0"
    generated_at: str

class PqcDecisionEngine:
    @classmethod
    def generate_recommendation(cls, finding: CanonicalFinding, asset_contexts: List[AssetContext]) -> RecommendationModel:
        # 1. Resolve Context
        ctx = ContextResolver.resolve(finding, asset_contexts)
        
        # 2. Eligibility Filtering
        eligibility_results = CandidateEligibilityEngine.filter_candidates(ctx)
        
        # 3. Trade-off Matrix Scoring
        policy = DecisionPolicy()
        scored_candidates = TradeOffMatrix.evaluate(eligibility_results, policy)
        
        # 4. Construct Output
        rejected = [{"candidate_id": r.candidate.catalogue_id, "reason": r.rejection_reason} 
                    for r in eligibility_results if not r.is_eligible]
        
        recommended_id = None
        alternatives = []
        trade_off_profile = {}
        candidate_scores = {}
        standards_refs = []
        
        if scored_candidates:
            recommended_id = scored_candidates[0].candidate_id
            alternatives = [s.candidate_id for s in scored_candidates[1:]]
            
            for s in scored_candidates:
                trade_off_profile[s.candidate_id] = s.breakdown
                candidate_scores[s.candidate_id] = s.total_score
                
            standards_refs.append(scored_candidates[0].candidate.standard_reference)
            
        return RecommendationModel(
            recommendation_id=f"rec-{finding.finding_id}",
            asset_ids=ctx.asset_ids,
            finding_ids=[ctx.finding_id],
            cryptographic_role=ctx.cryptographic_role,
            observed_configuration=ctx.observed_algorithm,
            recommended_candidate=recommended_id,
            alternative_candidates=alternatives,
            rejected_candidates=rejected,
            trade_off_profile=trade_off_profile,
            candidate_scores=candidate_scores,
            eligibility_results={r.candidate.catalogue_id: r.is_eligible for r in eligibility_results},
            required_prerequisites=["Verify library compatibility" if not ctx.libraries else "None"],
            limitations=["Insufficient context" if not ctx.libraries else "None"],
            confidence=0.8 if ctx.libraries else 0.4,
            evidence=[f"Observed algorithm: {ctx.observed_algorithm}", f"Resolved role: {ctx.cryptographic_role}"],
            standards_references=standards_refs,
            decision_policy_version=policy.version,
            generated_at=datetime.now(timezone.utc).isoformat()
        )
