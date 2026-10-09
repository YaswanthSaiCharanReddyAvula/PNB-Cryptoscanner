"""
Phase 5 — Roadmap Facade

Provides the main entry points for the API and background workers to generate
the roadmap from database models or live scan contexts.
"""

from typing import List, Dict, Any

from app.scanner.roadmap.models import TieredSecurityRoadmap
from app.scanner.roadmap.adapters.phase3_adapter import build_phase3_context
from app.scanner.roadmap.adapters.phase4_adapter import Phase4Context
from app.scanner.roadmap.item_generator import generate_roadmap
from app.scanner.convergence.aggregation import CanonicalInventory
from app.scanner.quantum.models import QuantumRiskAssessment, AssetQuantumRiskSummary


async def build_roadmap_from_scan(db: Any, scan_doc: Dict[str, Any]) -> TieredSecurityRoadmap:
    """
    Constructs the TieredSecurityRoadmap from MongoDB documents.
    Fetches required Phase 4 and Phase 5 contexts from DB.
    """
    domain = scan_doc.get("domain", "unknown")
    scan_id = scan_doc.get("scan_id", "")
    
    # 1. Fetch Phase 4 Data
    quantum_assessments = []
    quantum_summaries = []
    
    if scan_id:
        try:
            cursor = db["quantum_assessments"].find({"scan_id": scan_id})
            quantum_assessments = [a async for a in cursor]
            
            cursor2 = db["quantum_asset_summaries"].find({"scan_id": scan_id})
            quantum_summaries = [s async for s in cursor2]
        except Exception:
            pass
            
    # 2. Fetch Existing Roadmap Tasks (Phase 5 State)
    existing_tasks = []
    if domain:
        try:
            cursor3 = db["migration_tasks"].find({"domain": domain})
            existing_tasks = [t async for t in cursor3]
        except Exception:
            pass
    
    # 3. Reconstruct Phase 3 Canonical Inventory
    inventory_dict = scan_doc.get("canonical_inventory")
    if not inventory_dict:
        # Fallback to an empty inventory if not converged yet
        inventory = CanonicalInventory(scan_id=scan_id, target=domain)
    else:
        inventory = CanonicalInventory.model_validate(inventory_dict)
        
    phase3_context = build_phase3_context(inventory)
    
    # 4. Reconstruct Phase 4 Context
    # Filter out _id
    for a in quantum_assessments: a.pop("_id", None)
    for s in quantum_summaries: s.pop("_id", None)
    
    assessments = [QuantumRiskAssessment.model_validate(a) for a in quantum_assessments]
    summaries = [AssetQuantumRiskSummary.model_validate(s) for s in quantum_summaries]
    phase4_context = Phase4Context(assessments, summaries)
    
    # 5. Generate Roadmap
    roadmap = generate_roadmap(
        domain=domain,
        phase3_context=phase3_context,
        phase4_context=phase4_context,
        existing_items=existing_tasks
    )
    
    return roadmap
