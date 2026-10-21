"""
Phase 5 — Roadmap Generator

Orchestrates Phase 3 Context, Phase 4 Context, Knowledge Base, and Priority
Calculations to generate the authoritative Phase 5 Tiered Security Roadmap.
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone

from app.scanner.roadmap.models import (
    TieredSecurityRoadmap, RoadmapItem, RoadmapStatistics,
    PriorityDrivers, TaskStatus, RoadmapTrack, RoadmapItemState,
    PriorityTier, ActionType, EffortLevel
)
from app.scanner.roadmap.adapters.phase3_adapter import Phase3Context
from app.scanner.roadmap.adapters.phase4_adapter import Phase4Context
from app.scanner.roadmap.priority_calculator import calculate_priority_score, determine_tier, map_criticality, map_exposure
from app.scanner.roadmap.dag import build_dependency_graph
from app.scanner.roadmap.decision_engine import PqcDecisionEngine
from app.scanner.roadmap.models import ActionType, EffortLevel
from app.scanner.roadmap.timeline import generate_timeline
from app.scanner.roadmap.reconciliation import reconcile_roadmap

def generate_roadmap(
    domain: str,
    phase3_context: Phase3Context,
    phase4_context: Phase4Context,
    existing_items: List[dict] = None
) -> TieredSecurityRoadmap:
    """Generates the full authoritative roadmap."""
    
    if existing_items is None:
        existing_items = []
        
    generated_items: List[RoadmapItem] = []
    
    # 1. Generate Raw Items from Findings
    for finding in phase3_context.findings:
        
        # Use the PQC Decision Engine
        recommendation = PqcDecisionEngine.generate_recommendation(finding, finding.asset_contexts)
        
        # Classify the situation
        is_unknown = (
            recommendation.cryptographic_role in ("INSUFFICIENT_CONTEXT", "UNKNOWN")
            or recommendation.observed_configuration in ("UNKNOWN", "", None)
        )
        is_already_migrated = getattr(recommendation, "is_already_migrated", False)
        is_hybrid = getattr(recommendation, "is_hybrid", False)
        role = recommendation.cryptographic_role.upper().strip()
        is_symmetric = role in ("SYMMETRIC ENCRYPTION", "SYMMETRIC_ENCRYPTION")
        is_hash = role in ("HASH", "HASH_FUNCTION")

        if is_already_migrated:
            pqc_relevance = False
            title = f"Maintain and Monitor Post-Quantum Implementation ({recommendation.observed_configuration})"
            std_ref = f" under {', '.join(recommendation.standards_references)}" if recommendation.standards_references else ""
            description = f"Observed configuration {recommendation.observed_configuration} is already using post-quantum cryptography{std_ref}. Maintain monitoring and standards compliance."
            action_type = ActionType.MONITOR
            track = RoadmapTrack.QUANTUM_MIGRATION
            effort = EffortLevel.LOW
            rationale = recommendation.rationale or f"Observed {recommendation.observed_configuration} already uses standardized post-quantum cryptography."
        elif is_hybrid:
            pqc_relevance = False
            title = f"Validate Hybrid Post-Quantum Key Establishment ({recommendation.observed_configuration})"
            description = f"Observed configuration {recommendation.observed_configuration} uses hybrid key establishment. Validate protocol extension interoperability and monitor standard finalization."
            action_type = ActionType.VALIDATE
            track = RoadmapTrack.QUANTUM_MIGRATION
            effort = EffortLevel.LOW
            rationale = recommendation.rationale or "Transitional hybrid key exchange requires protocol extension validation."
        elif is_unknown:
            pqc_relevance = False
            title = f"Investigate Cryptographic Configuration ({recommendation.observed_configuration})"
            description = f"Observed {recommendation.observed_configuration} lacks sufficient context or algorithm identity. Conduct inventory and analysis to confirm the algorithm and operational role."
            action_type = ActionType.INVENTORY
            track = RoadmapTrack.CROSS_CUTTING
            effort = EffortLevel.LOW
            rationale = recommendation.rationale or "Insufficient cryptographic context to recommend replacement; active inventory required."
        elif is_symmetric:
            pqc_relevance = False
            if recommendation.recommended_candidate:
                title = f"Upgrade {recommendation.observed_configuration} to {recommendation.recommended_candidate}"
                description = f"Observed symmetric cipher {recommendation.observed_configuration} provides <128 bits of security against Grover quantum search. Upgrade to {recommendation.recommended_candidate}."
                action_type = ActionType.UPGRADE
                track = RoadmapTrack.CLASSICAL_SECURITY
                effort = EffortLevel.MEDIUM
                rationale = recommendation.rationale or f"Upgrade to {recommendation.recommended_candidate}."
            else:
                title = f"Monitor and Maintain Symmetric Encryption ({recommendation.observed_configuration})"
                description = f"Observed {recommendation.observed_configuration} provides >=128-bit quantum security level against Grover's algorithm. Maintain configuration."
                action_type = ActionType.MONITOR
                track = RoadmapTrack.CLASSICAL_SECURITY
                effort = EffortLevel.LOW
                rationale = recommendation.rationale or "Symmetric cipher meets quantum resistance requirements."
        elif is_hash:
            pqc_relevance = False
            if recommendation.recommended_candidate:
                title = f"Upgrade {recommendation.observed_configuration} to {recommendation.recommended_candidate}"
                description = f"Observed hash {recommendation.observed_configuration} is vulnerable to collision attacks. Upgrade to {recommendation.recommended_candidate}."
                action_type = ActionType.UPGRADE
                track = RoadmapTrack.CLASSICAL_SECURITY
                effort = EffortLevel.MEDIUM
                rationale = recommendation.rationale or f"Upgrade to {recommendation.recommended_candidate}."
            else:
                title = f"Monitor and Maintain Hash Function ({recommendation.observed_configuration})"
                description = f"Observed hash {recommendation.observed_configuration} provides sufficient collision and preimage resistance against quantum attacks. Maintain configuration."
                action_type = ActionType.MONITOR
                track = RoadmapTrack.CLASSICAL_SECURITY
                effort = EffortLevel.LOW
                rationale = recommendation.rationale or "Hash function meets quantum resistance requirements."
        else:
            # Asymmetric: Key Establishment / Digital Signatures
            pqc_relevance = recommendation.recommended_candidate is not None
            if recommendation.recommended_candidate:
                title = f"Migrate {recommendation.observed_configuration} to {recommendation.recommended_candidate}"
                description = f"Observed classical {role.lower().replace('_', ' ')} algorithm ({recommendation.observed_configuration}) is vulnerable to quantum cryptanalysis. Migrate to {recommendation.recommended_candidate}."
                action_type = ActionType.MIGRATE
                track = RoadmapTrack.QUANTUM_MIGRATION
                effort = EffortLevel.MEDIUM
                alts = f" Alternatives: {', '.join(recommendation.alternative_candidates)}." if recommendation.alternative_candidates else ""
                rationale = recommendation.rationale or f"Trade-off winner: {recommendation.recommended_candidate}.{alts}"
            else:
                title = f"Assess Post-Quantum Migration Path for {recommendation.observed_configuration}"
                description = f"No eligible post-quantum candidate currently identified in catalogue for {recommendation.observed_configuration} in role {recommendation.cryptographic_role}."
                action_type = ActionType.ASSESS
                track = RoadmapTrack.QUANTUM_MIGRATION
                effort = EffortLevel.LOW
                rationale = recommendation.rationale or "No eligible candidate found under current policy."

        item = RoadmapItem(
            title=title,
            description=description,
            asset_ids=[a.asset_id for a in finding.asset_contexts],
            finding_ids=[finding.finding_id],
            vulnerability_ids=[],
            track=track,
            action_type=action_type,
            effort=effort,
            rationale=rationale,
            prerequisites=recommendation.required_prerequisites,
            provenance=list(dict.fromkeys(finding.evidence + recommendation.evidence)),
            policy_version=getattr(recommendation, "policy_version", "1.0.0")
        )
        
        # 2. Contextualize Priority Drivers
        max_criticality = 0.0
        max_exposure = 0.0
        for a_ctx in finding.asset_contexts:
            crit = map_criticality(a_ctx.business_criticality)
            exp = map_exposure(a_ctx.internet_exposure)
            if crit > max_criticality: max_criticality = crit
            if exp > max_exposure: max_exposure = exp
            
        q_ctx = phase4_context.get_highest_quantum_context(item.asset_ids)
        
        sev_map = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "SAFE": 0, "UNKNOWN": 10}
        classical_risk = sev_map.get(finding.severity.upper(), 10)
        quantum_risk = q_ctx.quantum_risk_score if pqc_relevance else 0.0

        if is_already_migrated or is_hybrid:
            item.drivers = PriorityDrivers(
                classical_risk=0.0,
                quantum_risk=0.0,
                hndl=0.0,
                mosca_urgency=0.0,
                criticality=max_criticality,
                exposure=max_exposure,
                dependency_impact=0.0,
                confidence=recommendation.confidence
            )
            item.priority_score = calculate_priority_score(item.drivers)
            item.tier = PriorityTier.LOW
            item.urgency = "LOW"
            item.confidence = recommendation.confidence
        elif is_unknown:
            conf = min(finding.confidence, 0.2, recommendation.confidence)
            item.drivers = PriorityDrivers(
                classical_risk=classical_risk,
                quantum_risk=0.0,
                hndl=0.0,
                mosca_urgency=0.0,
                criticality=max_criticality,
                exposure=max_exposure,
                dependency_impact=0.0,
                confidence=conf
            )
            item.priority_score = calculate_priority_score(item.drivers)
            item.tier = PriorityTier.LOW
            item.urgency = "LOW"
            item.confidence = conf
        elif action_type == ActionType.MONITOR:
            item.drivers = PriorityDrivers(
                classical_risk=0.0,
                quantum_risk=0.0,
                hndl=0.0,
                mosca_urgency=0.0,
                criticality=max_criticality,
                exposure=max_exposure,
                dependency_impact=0.0,
                confidence=recommendation.confidence
            )
            item.priority_score = calculate_priority_score(item.drivers)
            item.tier = PriorityTier.LOW
            item.urgency = "LOW"
            item.confidence = recommendation.confidence
        else:
            conf = min(finding.confidence, q_ctx.confidence, recommendation.confidence)
            item.drivers = PriorityDrivers(
                classical_risk=classical_risk,
                quantum_risk=quantum_risk,
                hndl=q_ctx.hndl_exposure,
                mosca_urgency=q_ctx.mosca_urgency_score,
                criticality=max_criticality,
                exposure=max_exposure,
                dependency_impact=0.0,
                confidence=conf
            )
            item.priority_score = calculate_priority_score(item.drivers)
            item.tier = determine_tier(item.priority_score, q_ctx.mosca_status if pqc_relevance else "UNKNOWN")
            item.urgency = q_ctx.mosca_status if pqc_relevance else ("HIGH" if item.priority_score > 70 else "NORMAL")
            item.confidence = conf
        
        item.explanation.append(f"Confidence: {item.confidence}")
        if recommendation.limitations:
            item.explanation.append("Missing-context limitations: " + ", ".join(recommendation.limitations))
        if recommendation.standards_references:
            item.explanation.append("Standards references: " + ", ".join(recommendation.standards_references))
        item.explanation.append("Compatibility state and trade-off scores verified.")
        
        if max_criticality > 0: item.explanation.append("Affects critical assets.")
        if max_exposure > 0: item.explanation.append("Affects internet-facing assets.")
        if pqc_relevance:
            item.explanation.append(f"Quantum migration urgency: {q_ctx.mosca_status}")
            if q_ctx.hndl_exposure > 0:
                item.explanation.append(f"HNDL Exposure Score: {q_ctx.hndl_exposure}")

        generated_items.append(item)
            
    # 3. Reconcile with existing tasks
    reconciled_items = reconcile_roadmap(generated_items, existing_items)
    
    # 4. Dependency DAG
    # For a real implementation, we would wire up prerequisites based on KB and asset graphs
    # E.g., Upgrade -> Replace -> Test -> Deploy
    graph = build_dependency_graph(reconciled_items)
    
    # 5. Timeline Generation
    generate_timeline(reconciled_items, graph)
    
    # 6. Build final roadmap and stats
    roadmap = TieredSecurityRoadmap(
        scan_id=phase3_context.scan_id,
        domain=domain,
    )
    roadmap.items = reconciled_items
    roadmap.dependency_graph = graph
    
    stats = RoadmapStatistics()
    stats.total_tasks = len(reconciled_items)
    for item in reconciled_items:
        stats.by_track[item.track.value] = stats.by_track.get(item.track.value, 0) + 1
        stats.by_tier[item.tier.value] = stats.by_tier.get(item.tier.value, 0) + 1
        stats.by_status[item.status.value] = stats.by_status.get(item.status.value, 0) + 1
        if item.track == RoadmapTrack.QUANTUM_MIGRATION and item.tier == "CRITICAL":
            stats.critical_pqc_tasks += 1
            
    stats.blocked_tasks = len(graph.blocked_tasks)
    roadmap.statistics = stats
    
    return roadmap
