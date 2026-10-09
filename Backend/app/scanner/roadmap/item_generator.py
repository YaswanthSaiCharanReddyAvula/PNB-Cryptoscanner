"""
Phase 5 — Roadmap Generator

Orchestrates Phase 3 Context, Phase 4 Context, Knowledge Base, and Priority
Calculations to generate the authoritative Phase 5 Tiered Security Roadmap.
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone

from app.scanner.roadmap.models import (
    TieredSecurityRoadmap, RoadmapItem, RoadmapStatistics,
    PriorityDrivers, TaskStatus, RoadmapTrack, RoadmapItemState
)
from app.scanner.roadmap.adapters.phase3_adapter import Phase3Context
from app.scanner.roadmap.adapters.phase4_adapter import Phase4Context
from app.scanner.roadmap.knowledge_base import get_recommendations_for_finding
from app.scanner.roadmap.priority_calculator import calculate_priority_score, determine_tier, map_criticality, map_exposure
from app.scanner.roadmap.dag import build_dependency_graph
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
        
        # Determine finding algorithm context (extracted naively from title/description for now, normally from finding details)
        algorithm = None
        if "ECDHE" in finding.finding_type.upper():
            algorithm = "ECDHE"
        elif "RSA" in finding.finding_type.upper():
            algorithm = "RSA"
            
        kbs = get_recommendations_for_finding(finding.finding_type, algorithm)
        
        for kb in kbs:
            item = RoadmapItem(
                title=kb.title,
                description=kb.description,
                asset_ids=[a.asset_id for a in finding.asset_contexts],
                finding_ids=[finding.finding_id],
                vulnerability_ids=[], # from Phase 3 CVEs if applicable
                track=kb.track,
                action_type=kb.action_type,
                effort=kb.default_effort,
                rationale=kb.solution,
            )
            
            # 2. Contextualize Priority Drivers
            # Aggregate max criticality and exposure across all affected assets
            max_criticality = 0.0
            max_exposure = 0.0
            for a_ctx in finding.asset_contexts:
                crit = map_criticality(a_ctx.business_criticality)
                exp = map_exposure(a_ctx.internet_exposure)
                if crit > max_criticality: max_criticality = crit
                if exp > max_exposure: max_exposure = exp
                
            # Fetch Quantum Context
            q_ctx = phase4_context.get_highest_quantum_context(item.asset_ids)
            
            # Classical risk mapped from severity
            sev_map = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "SAFE": 0, "UNKNOWN": 10}
            classical_risk = sev_map.get(finding.severity.upper(), 10)
            if not kb.classical_relevance:
                classical_risk = 0
                
            quantum_risk = q_ctx.quantum_risk_score if kb.pqc_relevance else 0.0
                
            item.drivers = PriorityDrivers(
                classical_risk=classical_risk,
                quantum_risk=quantum_risk,
                hndl=q_ctx.hndl_exposure,
                mosca_urgency=q_ctx.mosca_urgency_score,
                criticality=max_criticality,
                exposure=max_exposure,
                dependency_impact=0.0, # Computed later if needed
                confidence=min(finding.confidence, q_ctx.confidence)
            )
            
            item.priority_score = calculate_priority_score(item.drivers)
            item.tier = determine_tier(item.priority_score, q_ctx.mosca_status)
            item.urgency = q_ctx.mosca_status if kb.pqc_relevance else ("HIGH" if item.priority_score > 70 else "NORMAL")
            
            # Add explainability
            item.explanation.append(f"Derived from knowledge base: {kb.title}")
            if max_criticality > 0: item.explanation.append(f"Affects critical assets.")
            if max_exposure > 0: item.explanation.append(f"Affects internet-facing assets.")
            if kb.pqc_relevance:
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
