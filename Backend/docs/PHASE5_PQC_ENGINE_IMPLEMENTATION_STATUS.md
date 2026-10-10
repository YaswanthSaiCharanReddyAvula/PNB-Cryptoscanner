# Phase 5 PQC Engine Implementation Status

## 1. Structured PQC Candidate Filtering
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/eligibility.py`
- **Required Change**: Implement a structured filter that takes Phase 3 context and evaluates which PQC algorithms are valid candidates.
- **Dependencies**: Structured Algorithm Catalogue, Phase 3 context resolver.
- **Tests**: Verify candidates are correctly included/excluded based on role, protocol, and library constraints.
- **Risks**: Incorrect filtering could exclude viable algorithms or include incompatible ones.
- **Acceptance Criteria**: The system outputs a set of strictly eligible candidates with reasons for rejections.

## 2. Context-Aware Algorithm Selection
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/context_resolver.py`
- **Required Change**: Build a context resolver that uses canonical Phase 3 data (assets, actual components) to determine role and requirements.
- **Dependencies**: Phase 3 Context model.
- **Tests**: Ensure the resolver accurately identifies cryptographic purpose and operational constraints from diverse Phase 3 inputs.
- **Risks**: Loss of context or mishandling of ambiguous Phase 3 data.
- **Acceptance Criteria**: The engine correctly deduces context without relying on `finding_type` substrings.

## 3. Multidimensional Algorithm Trade-off Matrix
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/trade_off.py`
- **Required Change**: Implement a scoring matrix based on policy weights and normalized metrics.
- **Dependencies**: Performance and Size metadata.
- **Tests**: Ensure that ranking respects hard constraints and weights correctly.
- **Risks**: Over-indexing on a specific metric like latency at the cost of security.
- **Acceptance Criteria**: The engine scores candidates and outputs a ranked list with transparent explanations.

## 4. Parameter-Set Metadata and Standardized Security-Category Metadata
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/quantum/catalogue.json`
- **Required Change**: Create a JSON-based catalogue with NIST categories and parameter sets (e.g., ML-KEM-768).
- **Dependencies**: None.
- **Tests**: Schema validation of the catalogue JSON.
- **Risks**: Stale or incorrect standards definitions.
- **Acceptance Criteria**: The catalogue accurately represents NIST standards, variants, and security categories.

## 5. Key, Ciphertext, and Signature Size Comparisons
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/trade_off.py`
- **Required Change**: Add size metrics to the catalogue and expose them in the trade-off evaluation.
- **Dependencies**: Structured Algorithm Catalogue.
- **Tests**: Ensure matrix correctly penalizes candidates exceeding predefined limits.
- **Risks**: Incorrect sizes lead to unusable recommendations.
- **Acceptance Criteria**: Candidates are evaluated based on their size footprints (bytes) against environment constraints.

## 6. Evidence-Backed Performance and Benchmark Data
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/quantum/catalogue.json`, `Backend/app/scanner/quantum/catalogue.py`
- **Required Change**: Include performance profiles (latency, throughput) with provenance in the catalogue.
- **Dependencies**: Structured Algorithm Catalogue.
- **Tests**: Ensure unknown performance doesn't score higher than known performance.
- **Risks**: Using incomparable benchmarks across different environments.
- **Acceptance Criteria**: The matrix integrates benchmark data correctly, noting its source and methodology.

## 7. Actual Library and Protocol Compatibility Validation
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/eligibility.py`
- **Required Change**: Build an eligibility filter checking Phase 3 actual evidence against catalogue support matrices.
- **Dependencies**: Phase 3 Context, Catalogue Implementation Support.
- **Tests**: Reject candidates unsupported by the observed TLS version or library.
- **Risks**: False positives leading to broken deployments.
- **Acceptance Criteria**: Only demonstrably compatible (or conditionally valid) algorithms are marked eligible.

## 8. Hybrid Deployment Compatibility Analysis
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/item_generator.py`
- **Required Change**: Model hybrid constructions explicitly with combined metadata and specific compatibility rules.
- **Dependencies**: Structured Algorithm Catalogue.
- **Tests**: Ensure the engine correctly models the combined sizes and protocol limits of hybrid approaches.
- **Risks**: Invalid assumptions about hybrid component interactions.
- **Acceptance Criteria**: Hybrid deployments are evaluated holistically as distinct entities.

## 9. Structured Uncertainty and Unsupported-Context Handling
- **Current state**: `COMPLETED`
- **Files & Reachability**: `Backend/app/scanner/roadmap/eligibility.py`, `Backend/app/scanner/roadmap/trade_off.py`
- **Required Change**: Add confidence scores to compatibility and output explicit `INSUFFICIENT_CONTEXT` when needed.
- **Dependencies**: Phase 3 Context resolver, API output models.
- **Tests**: Verify missing data yields an unknown state rather than an assumed positive.
- **Risks**: Unwarranted confidence in uncertain recommendations.
- **Acceptance Criteria**: Uncertainty is propagated to the frontend cleanly.

## 10. A Single Authoritative Recommendation Engine
- **Current state**: `COMPLETED`
- **Files & Reachability**: 
    - `Backend/app/modules/recommendation_engine.py`
    - `Backend/app/modules/security_roadmap.py`
    - `Backend/app/scanner/engines/reporting.py`
    - `Backend/app/scanner/roadmap/decision_engine.py`
- **Required Change**: Create a central `PqcDecisionEngine` and route existing callers to it.
- **Dependencies**: All above capabilities.
- **Tests**: Ensure API responses and frontend views remain intact.
- **Risks**: Breaking existing consumers during transition.
- **Acceptance Criteria**: Legacy mapping engines are deprecated and routed through the new authoritative engine.
