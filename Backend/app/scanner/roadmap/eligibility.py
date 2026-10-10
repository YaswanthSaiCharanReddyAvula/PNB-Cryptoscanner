import re
from typing import List, Dict, Tuple
from app.scanner.roadmap.context_resolver import CryptographicContext
from app.scanner.quantum.catalogue import CatalogueManager, CatalogueEntry

class EligibilityResult:
    def __init__(self, candidate: CatalogueEntry, is_eligible: bool, rejection_reason: str = None, compatibility_state: str = "NOT_APPLICABLE"):
        self.candidate = candidate
        self.is_eligible = is_eligible
        self.rejection_reason = rejection_reason
        self.compatibility_state = compatibility_state

def _parse_lib_version(lib_str: str) -> Tuple[str, str, bool]:
    match = re.match(r"^([a-z0-9_\-]+)[\s_]+v?(\d+(?:\.\d+)*)(\+?)$", lib_str.strip().lower())
    if match:
        name = match.group(1).replace("-", "_")
        return name, match.group(2), match.group(3) == "+"
    return lib_str.strip().lower(), None, False

def _compare_versions(v_ctx: str, v_req: str, is_minimum: bool) -> bool:
    if not v_ctx or not v_req:
        return False
    try:
        parts_ctx = [int(x) for x in v_ctx.split('.')]
        parts_req = [int(x) for x in v_req.split('.')]
        # Pad shorter list
        max_len = max(len(parts_ctx), len(parts_req))
        parts_ctx += [0] * (max_len - len(parts_ctx))
        parts_req += [0] * (max_len - len(parts_req))
        
        if is_minimum:
            return parts_ctx >= parts_req
        return parts_ctx == parts_req
    except ValueError:
        return v_ctx == v_req

def evaluate_library_compatibility(context_libraries: List[str], candidate_support: List[str]) -> str:
    if not context_libraries or not candidate_support:
        return "UNVERIFIED"
        
    supported_names = 0
    for ctx_lib in context_libraries:
        ctx_name, ctx_ver, _ = _parse_lib_version(ctx_lib)
        for req_lib in candidate_support:
            req_name, req_ver, req_is_min = _parse_lib_version(req_lib)
            if ctx_name == req_name:
                supported_names += 1
                if req_ver:
                    if ctx_ver:
                        if _compare_versions(ctx_ver, req_ver, req_is_min):
                            return "SUPPORTED"
                        # We don't return UNSUPPORTED immediately; maybe another ctx_lib matches
                    else:
                        # Required version but we only have name, we don't know for sure
                        pass
                else:
                    return "SUPPORTED"
                    
    if supported_names > 0:
        return "UNSUPPORTED"
        
    return "UNVERIFIED"

class CandidateEligibilityEngine:
    @classmethod
    def filter_candidates(cls, context: CryptographicContext) -> List[EligibilityResult]:
        """Filters catalogue candidates based on the observed cryptographic context."""
        
        all_candidates = CatalogueManager.get_all()
        results = []

        for candidate in all_candidates:
            # 1. Role Compatibility
            if candidate.cryptographic_role != context.cryptographic_role:
                results.append(EligibilityResult(candidate, False, "ROLE_MISMATCH", "NOT_APPLICABLE"))
                continue
                
            # 2. Standardization / Policy Filter
            if candidate.standardization_status not in ["STANDARDIZED", "DRAFT"]:
                results.append(EligibilityResult(candidate, False, "STANDARDIZATION_STATUS_NOT_ALLOWED", "NOT_APPLICABLE"))
                continue
                
            # 3. Size Limits
            if context.memory_constraint_bytes is not None:
                total_key_bytes = (candidate.public_key_bytes or 0) + (candidate.private_key_bytes or 0)
                if total_key_bytes > context.memory_constraint_bytes:
                    results.append(EligibilityResult(candidate, False, "MEMORY_LIMIT_EXCEEDED", "NOT_APPLICABLE"))
                    continue
                    
            if context.payload_limit_bytes is not None:
                payload_bytes = (candidate.ciphertext_bytes or 0) + (candidate.signature_bytes or 0)
                if payload_bytes > context.payload_limit_bytes:
                    results.append(EligibilityResult(candidate, False, "SIZE_LIMIT_EXCEEDED", "NOT_APPLICABLE"))
                    continue

            # 4. Evidence-Backed Library Support Filter
            compat_state = evaluate_library_compatibility(context.libraries, candidate.implementation_support)
            if compat_state == "UNSUPPORTED":
                results.append(EligibilityResult(candidate, False, "LIBRARY_UNSUPPORTED", compat_state))
                continue

            # Passed all filters
            results.append(EligibilityResult(candidate, True, None, compat_state))

        return results
