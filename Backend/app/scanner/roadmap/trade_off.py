from typing import List, Dict
from pydantic import BaseModel
from app.scanner.roadmap.eligibility import EligibilityResult
from app.scanner.quantum.catalogue import CatalogueEntry, CatalogueManager

class DecisionPolicy(BaseModel):
    version: str = "1.0.0"
    weights: Dict[str, float] = {
        "security_category": 0.4,
        "standardization": 0.3,
        "size_efficiency": 0.3
    }
    missing_data_penalty: float = 0.5

class ScoredCandidate(BaseModel):
    candidate_id: str
    name: str
    total_score: float
    breakdown: Dict[str, float]
    candidate: CatalogueEntry

class TradeOffMatrix:
    @classmethod
    def evaluate(cls, eligible_results: List[EligibilityResult], policy: DecisionPolicy = DecisionPolicy()) -> List[ScoredCandidate]:
        scored_candidates = []
        
        # Dynamic sizes for normalization based on catalogue
        all_candidates = CatalogueManager.get_all()
        max_size_in_catalog = 0
        for cat in all_candidates:
            cat_size = (cat.public_key_bytes or 0) + (cat.private_key_bytes or 0) + (cat.ciphertext_bytes or 0) + (cat.signature_bytes or 0)
            if cat_size > max_size_in_catalog:
                max_size_in_catalog = cat_size
                
        # Handle empty catalogue, missing values, and zero denominator
        normalization_bound = max_size_in_catalog if max_size_in_catalog > 0 else 10000
        
        for result in eligible_results:
            if not result.is_eligible:
                continue
                
            candidate = result.candidate
            breakdown = {}
            
            # 1. Security Category Score (Higher is better, normalized to 0-1)
            # Assuming max category is 5
            sec_cat = candidate.security_category or (3 * policy.missing_data_penalty)
            breakdown["security_category"] = min(sec_cat / 5.0, 1.0)
            
            # 2. Standardization Score (STANDARDIZED > DRAFT)
            std_score = 1.0 if candidate.standardization_status == "STANDARDIZED" else 0.5
            breakdown["standardization"] = std_score
            
            # 3. Size Efficiency Score (Smaller is better, inverted)
            total_size = (candidate.public_key_bytes or 0) + (candidate.private_key_bytes or 0) + (candidate.ciphertext_bytes or 0) + (candidate.signature_bytes or 0)
            if total_size == 0:
                size_score = policy.missing_data_penalty
            else:
                size_score = max(0.0, 1.0 - (total_size / normalization_bound))
            breakdown["size_efficiency"] = size_score
            
            # Calculate total weighted score
            total = sum(breakdown[k] * policy.weights.get(k, 0.0) for k in breakdown.keys())
            
            scored_candidates.append(ScoredCandidate(
                candidate_id=candidate.catalogue_id,
                name=candidate.name,
                total_score=total,
                breakdown=breakdown,
                candidate=candidate
            ))
            
        # Sort by total score descending, then by candidate_id ascending for stable deterministic tie-breaking
        scored_candidates.sort(key=lambda x: (-x.total_score, x.candidate_id))
        return scored_candidates
