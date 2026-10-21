from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.scanner.roadmap.adapters.phase3_adapter import NormalizedFindingContext as CanonicalFinding, NormalizedAssetContext as AssetContext
from app.scanner.roadmap.context_resolver import ContextResolver
from app.scanner.roadmap.eligibility import CandidateEligibilityEngine
from app.scanner.roadmap.trade_off import TradeOffMatrix, DecisionPolicy

from app.scanner.engines.crypto_normalization import CryptoNormalization

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
    policy_version: str = "1.0.0"
    generated_at: str
    is_already_migrated: bool = False
    is_hybrid: bool = False
    rationale: str = ""

class PqcDecisionEngine:
    @classmethod
    def generate_recommendation(cls, finding: CanonicalFinding, asset_contexts: List[AssetContext]) -> RecommendationModel:
        # 1. Resolve Context
        ctx = ContextResolver.resolve(finding, asset_contexts)
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # 2. Check for Unknown / Insufficient Context
        if ctx.cryptographic_role in ("INSUFFICIENT_CONTEXT", "UNKNOWN") or ctx.observed_algorithm in ("UNKNOWN", "", None):
            return RecommendationModel(
                recommendation_id=f"rec-{finding.finding_id}",
                asset_ids=ctx.asset_ids,
                finding_ids=[ctx.finding_id],
                cryptographic_role="INSUFFICIENT_CONTEXT",
                observed_configuration=ctx.observed_algorithm or "UNKNOWN",
                recommended_candidate=None,
                alternative_candidates=[],
                rejected_candidates=[],
                trade_off_profile={},
                candidate_scores={},
                eligibility_results={},
                required_prerequisites=["Verify cryptographic algorithm and operational role via asset inspection"],
                limitations=["Insufficient context: missing algorithm identity or cryptographic role"],
                confidence=min(finding.confidence, 0.2),
                evidence=[f"Observed algorithm: {ctx.observed_algorithm}", f"Resolved role: {ctx.cryptographic_role}", "Ambiguous or unknown cryptographic primitive; cannot recommend replacement"],
                standards_references=[],
                is_already_migrated=False,
                is_hybrid=False,
                rationale="Insufficient cryptographic context to recommend a replacement algorithm. Perform active inventory and analysis to confirm the algorithm and operational role.",
                generated_at=now_iso
            )

        upper_alg = ctx.observed_algorithm.upper().strip()

        # 3. Check for Already Standardized PQC
        pqc_standards_map = {
            "ML-KEM-512": "FIPS 203",
            "ML-KEM-768": "FIPS 203",
            "ML-KEM-1024": "FIPS 203",
            "KYBER": "FIPS 203",
            "CRYSTALS-KYBER": "FIPS 203",
            "ML-DSA-44": "FIPS 204",
            "ML-DSA-65": "FIPS 204",
            "ML-DSA-87": "FIPS 204",
            "DILITHIUM": "FIPS 204",
            "CRYSTALS-DILITHIUM": "FIPS 204",
            "SLH-DSA": "FIPS 205",
            "SLH-DSA-SHA2-128S": "FIPS 205",
            "SPHINCS+": "FIPS 205",
            "FALCON": "NIST Round 3",
        }
        matched_std = pqc_standards_map.get(upper_alg)
        if not matched_std:
            for k, std in pqc_standards_map.items():
                if k in upper_alg:
                    matched_std = std
                    break

        if matched_std and "HYBRID" not in upper_alg and "X25519-ML-KEM" not in upper_alg and "X25519KYBER" not in upper_alg:
            return RecommendationModel(
                recommendation_id=f"rec-{finding.finding_id}",
                asset_ids=ctx.asset_ids,
                finding_ids=[ctx.finding_id],
                cryptographic_role=ctx.cryptographic_role,
                observed_configuration=ctx.observed_algorithm,
                recommended_candidate=None,
                alternative_candidates=[],
                rejected_candidates=[],
                trade_off_profile={},
                candidate_scores={},
                eligibility_results={},
                required_prerequisites=["Maintain operational compatibility with peer implementations"],
                limitations=[],
                confidence=1.0,
                evidence=[f"Observed algorithm: {ctx.observed_algorithm}", f"Already standardized PQC under {matched_std}"],
                standards_references=[matched_std],
                is_already_migrated=True,
                is_hybrid=False,
                rationale=f"Observed {ctx.observed_algorithm} is already a standardized post-quantum cryptographic algorithm ({matched_std}). Maintain current configuration.",
                generated_at=now_iso
            )

        # 4. Check for Transitional Hybrid Configurations
        is_hybrid = (
            "X25519-ML-KEM" in upper_alg
            or "X25519KYBER" in upper_alg
            or ("KYBER" in upper_alg and ("X25519" in upper_alg or "P256" in upper_alg))
            or "HYBRID" in upper_alg
        )
        if is_hybrid:
            return RecommendationModel(
                recommendation_id=f"rec-{finding.finding_id}",
                asset_ids=ctx.asset_ids,
                finding_ids=[ctx.finding_id],
                cryptographic_role="KEY_ESTABLISHMENT",
                observed_configuration=ctx.observed_algorithm,
                recommended_candidate=None,
                alternative_candidates=[],
                rejected_candidates=[],
                trade_off_profile={},
                candidate_scores={},
                eligibility_results={},
                required_prerequisites=["Verify client and peer hybrid TLS extension support"],
                limitations=["Requires hybrid protocol extension support on all communicating endpoints"],
                confidence=0.8,
                evidence=[f"Observed algorithm: {ctx.observed_algorithm}", "Transitional hybrid key exchange (classical ECDH + PQC KEM)"],
                standards_references=["IETF Draft TLS Hybrid"],
                is_already_migrated=False,
                is_hybrid=True,
                rationale=f"Observed {ctx.observed_algorithm} is an active transitional hybrid key agreement scheme. Validate peer/client protocol extension compatibility and monitor final standards adoption.",
                generated_at=now_iso
            )

        # 5. Check for Symmetric Encryption
        if ctx.cryptographic_role in ("SYMMETRIC ENCRYPTION", "SYMMETRIC_ENCRYPTION"):
            bits = CryptoNormalization.extract_bits(upper_alg) or 128
            if bits >= 256 or "CHACHA20" in upper_alg:
                return RecommendationModel(
                    recommendation_id=f"rec-{finding.finding_id}",
                    asset_ids=ctx.asset_ids,
                    finding_ids=[ctx.finding_id],
                    cryptographic_role="SYMMETRIC_ENCRYPTION",
                    observed_configuration=ctx.observed_algorithm,
                    recommended_candidate=None,
                    alternative_candidates=[],
                    rejected_candidates=[],
                    trade_off_profile={},
                    candidate_scores={},
                    eligibility_results={},
                    required_prerequisites=[],
                    limitations=[],
                    confidence=0.9,
                    evidence=[f"Observed algorithm: {ctx.observed_algorithm}", "Symmetric encryption with >=256-bit key length provides 128-bit quantum resistance"],
                    standards_references=["NIST SP 800-131A Rev 2", "CNSA 2.0"],
                    is_already_migrated=False,
                    is_hybrid=False,
                    rationale=f"Observed {ctx.observed_algorithm} provides >=128 bits of effective security against Grover's quantum attack. Maintain 256-bit symmetric cipher configuration.",
                    generated_at=now_iso
                )
            else:
                return RecommendationModel(
                    recommendation_id=f"rec-{finding.finding_id}",
                    asset_ids=ctx.asset_ids,
                    finding_ids=[ctx.finding_id],
                    cryptographic_role="SYMMETRIC_ENCRYPTION",
                    observed_configuration=ctx.observed_algorithm,
                    recommended_candidate="AES-256-GCM",
                    alternative_candidates=["AES-256-CBC"],
                    rejected_candidates=[],
                    trade_off_profile={},
                    candidate_scores={},
                    eligibility_results={},
                    required_prerequisites=["Ensure application support for AES-256 cipher suites"],
                    limitations=[],
                    confidence=0.9,
                    evidence=[f"Observed algorithm: {ctx.observed_algorithm}", "Symmetric cipher with <256 bits must upgrade to AES-256 for post-quantum resistance"],
                    standards_references=["NIST SP 800-131A Rev 2", "FIPS 197"],
                    is_already_migrated=False,
                    is_hybrid=False,
                    rationale=f"Observed {ctx.observed_algorithm} provides <128 bits of security against Grover quantum search. Upgrade key length to AES-256 (NIST SP 800-131A / CNSA 2.0).",
                    generated_at=now_iso
                )

        # 6. Check for Hash
        if ctx.cryptographic_role == "HASH":
            is_weak_hash = any(h in upper_alg for h in ("MD5", "SHA-1", "SHA1"))
            if is_weak_hash:
                return RecommendationModel(
                    recommendation_id=f"rec-{finding.finding_id}",
                    asset_ids=ctx.asset_ids,
                    finding_ids=[ctx.finding_id],
                    cryptographic_role="HASH",
                    observed_configuration=ctx.observed_algorithm,
                    recommended_candidate="SHA-256",
                    alternative_candidates=["SHA-384", "SHA-512"],
                    rejected_candidates=[],
                    trade_off_profile={},
                    candidate_scores={},
                    eligibility_results={},
                    required_prerequisites=["Verify hash function support across consuming systems"],
                    limitations=[],
                    confidence=0.9,
                    evidence=[f"Observed algorithm: {ctx.observed_algorithm}", "Deprecated hash algorithm must be upgraded to SHA-2 family"],
                    standards_references=["FIPS 180-4"],
                    is_already_migrated=False,
                    is_hybrid=False,
                    rationale=f"Observed {ctx.observed_algorithm} is cryptographically broken and vulnerable to collision and preimage attacks. Upgrade to SHA-256 or SHA-384.",
                    generated_at=now_iso
                )
            else:
                return RecommendationModel(
                    recommendation_id=f"rec-{finding.finding_id}",
                    asset_ids=ctx.asset_ids,
                    finding_ids=[ctx.finding_id],
                    cryptographic_role="HASH",
                    observed_configuration=ctx.observed_algorithm,
                    recommended_candidate=None,
                    alternative_candidates=[],
                    rejected_candidates=[],
                    trade_off_profile={},
                    candidate_scores={},
                    eligibility_results={},
                    required_prerequisites=[],
                    limitations=[],
                    confidence=0.9,
                    evidence=[f"Observed algorithm: {ctx.observed_algorithm}", "Secure hash provides sufficient quantum collision/preimage resistance"],
                    standards_references=["FIPS 180-4"],
                    is_already_migrated=False,
                    is_hybrid=False,
                    rationale=f"Observed {ctx.observed_algorithm} provides >=128 bits of collision/preimage resistance against quantum attacks. Maintain current hash configuration.",
                    generated_at=now_iso
                )

        # 7. Asymmetric Cryptography: Key Establishment and Digital Signatures
        # 7.1. Eligibility Filtering via Catalogue
        eligibility_results = CandidateEligibilityEngine.filter_candidates(ctx)
        
        # 7.2. Trade-off Matrix Scoring
        policy = DecisionPolicy()
        scored_candidates = TradeOffMatrix.evaluate(eligibility_results, policy)
        
        # 7.3. Construct Output
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
            rationale_text = f"Trade-off winner: {recommended_id}. Alternatives: {', '.join(alternatives)}."
        else:
            rationale_text = f"No eligible post-quantum candidate found in catalogue for role {ctx.cryptographic_role} under specified constraints."
            
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
            limitations=["No eligible candidate found" if not scored_candidates else ("Insufficient context" if not ctx.libraries else "None")],
            confidence=0.8 if ctx.libraries and scored_candidates else 0.4,
            evidence=[f"Observed algorithm: {ctx.observed_algorithm}", f"Resolved role: {ctx.cryptographic_role}"],
            standards_references=standards_refs,
            decision_policy_version=policy.version,
            is_already_migrated=False,
            is_hybrid=False,
            rationale=rationale_text,
            generated_at=now_iso
        )
