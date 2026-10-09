# Phase 5 Implementation Report

## Executive Summary
The Phase 5 Tiered Security Roadmap Engine has been completely re-architected. It is no longer a naive regex-based sorter on the frontend or a flat-list generator in the API. It is now a true backend-authoritative, evidence-driven, asset-aware, and dependency-aware system.

## Changes Made
1. **Domain Models (`models.py`)**: Introduced robust models for `RoadmapItem`, `RoadmapDependencyGraph`, `TimelineWindow`, and `PriorityDrivers`. These reflect authoritative backend semantics.
2. **Phase 3 & 4 Adapters (`phase3_adapter.py`, `phase4_adapter.py`)**: The engine now extracts asset criticality, internet exposure, quantum risk, and HNDL scores securely from the Phase 3 converged canonical models and Phase 4 risk assessments.
3. **Remediation Knowledge Base (`knowledge_base.py`)**: Created a structured mapping of actionable solutions based on identified algorithm and protocol vulnerabilities, separating `CLASSICAL_SECURITY` from `QUANTUM_MIGRATION` tracks.
4. **Priority Engine (`priority_calculator.py`)**: Built a deterministic calculator that weights base risk against exposure and criticality multipliers, explicitly surfacing HNDL and Mosca urgency, to compute a deterministic `PriorityTier`.
5. **DAG Engine (`dag.py`) & Timeline Engine (`timeline.py`)**: Implemented cycle detection and topological sorting to ensure tasks block properly (e.g., Upgrade -> Replace -> Test -> Deploy) and are scheduled into appropriate timeline windows (`IMMEDIATE`, `SHORT_TERM`, etc.).
6. **Reconciliation Engine (`reconciliation.py`)**: Automatically preserves human modifications (like status and owner) across rescans using deterministic semantic signatures.
7. **Frontend Updates (`SecurityRoadmap.tsx`)**: Removed UI calculations for priority and risk. The React frontend now acts as a dumb consumer, purely displaying the backend's `Tier`, `PriorityScore`, `TimelineWindow`, and explanations.

## Satisfaction of Non-Negotiable Rules
- **Backend Authority**: The frontend no longer guesses the tier or priority. All semantics are defined in `priority_calculator.py` and `models.py`.
- **Deterministic**: Given the same scan (same findings, same exposures), the DAG, Priority Score, and Tier will always map exactly the same way via `generate_roadmap()`.
- **Phase 3 & 4 Integrity**: The legacy systems (`crypto_cbom.py`) now query the MongoDB `quantum_assessments` and `quantum_asset_summaries` collections via the `facade`, fully respecting Phase 4 without flattening or mocking the data.
- **Explainability**: Every roadmap item now includes `rationale` and `explanation` lists (e.g., "Affects internet-facing assets") which are fed directly into the React UI.

## Unresolved Tech Debt
- **DAG Prerequisite Linking**: Currently the DAG groups items by asset, but strict dependency linking between specific KB recommendations (e.g., specific Upgrade task blocking a specific Replace task) is mocked and requires the KB entries to define more explicit precondition IDs.
- **Full Historical Sync**: The reconciliation engine does a naive signature match based on action types and assets. In a large environment with moving IP addresses, the canonical `asset_id` must remain stable across Phase 3 runs for the Phase 5 roadmap to retain task state over months.
- **Legacy Fallbacks**: The old `security_roadmap.py` still exists in `app.modules`. It is safely bypassed by `crypto_cbom.py` and `admin_governance.py` but should be deleted in Phase 6 cleanup.
