"""
Phase 5 — Rescan Reconciliation Engine

Reconciles newly generated roadmap items with historical state from the database.
Preserves manual task state (status, owner, etc.) and computes reconciliation states (NEW, RESOLVED, etc.).
"""

from typing import List, Dict
from app.scanner.roadmap.models import RoadmapItem, RoadmapItemState, TaskStatus

def reconcile_roadmap(new_items: List[RoadmapItem], existing_items: List[dict]) -> List[RoadmapItem]:
    """
    Compares newly generated roadmap items with existing ones from DB.
    Preserves manual modifications and sets appropriate reconciliation states.
    """
    # Create lookup map for existing items based on a semantic signature.
    # A task's identity is defined by its action_type, track, and finding/asset associations.
    existing_map = {}
    for e in existing_items:
        # Construct identity key
        finding_keys = sorted(e.get("finding_ids", []))
        asset_keys = sorted(e.get("asset_ids", []))
        sig = f"{e.get('track')}_{e.get('action_type')}_{','.join(finding_keys)}_{','.join(asset_keys)}"
        existing_map[sig] = e

    reconciled_items = []
    matched_sigs = set()

    for item in new_items:
        finding_keys = sorted(item.finding_ids)
        asset_keys = sorted(item.asset_ids)
        sig = f"{item.track.value}_{item.action_type.value}_{','.join(finding_keys)}_{','.join(asset_keys)}"
        
        if sig in existing_map:
            matched_sigs.add(sig)
            old = existing_map[sig]
            
            # Preserve identity
            item.roadmap_item_id = old.get("roadmap_item_id", item.roadmap_item_id)
            
            # Preserve manual state
            if old.get("status"):
                try:
                    item.status = TaskStatus(old["status"])
                except ValueError:
                    pass
            if old.get("owner"):
                item.owner = old["owner"]
                
            # Determine Reconciliation State
            # If priority changed significantly
            old_priority = old.get("priority_score", 0.0)
            if abs(item.priority_score - old_priority) > 10.0:
                item.reconciliation_state = RoadmapItemState.CHANGED
                item.explanation.append(f"Priority changed from {old_priority} to {item.priority_score}.")
            elif item.status in (TaskStatus.WAIVED, TaskStatus.COMPLETED):
                item.reconciliation_state = RoadmapItemState.UNCHANGED # State maintained
            else:
                item.reconciliation_state = RoadmapItemState.UNCHANGED
        else:
            item.reconciliation_state = RoadmapItemState.NEW
            
        reconciled_items.append(item)
        
    # Check for resolved/superseded items
    # Items that exist in DB but not in new scan are assumed resolved,
    # UNLESS they were already completed/waived.
    # In a full implementation, we'd also check if the asset is missing vs scanned.
    # For now, mark them RESOLVED and include them in the roadmap.
    for sig, old in existing_map.items():
        if sig not in matched_sigs:
            # Reconstruct RoadmapItem from dictionary (simplified)
            old_status = old.get("status", "PLANNED")
            if old_status not in ("COMPLETED", "WAIVED", "CANCELLED"):
                # Missing from new scan -> Resolved
                resolved_item = RoadmapItem(**old)
                resolved_item.reconciliation_state = RoadmapItemState.RESOLVED
                resolved_item.status = TaskStatus.COMPLETED
                resolved_item.explanation.append("Automatically marked resolved as finding is no longer present in scan.")
                reconciled_items.append(resolved_item)

    return reconciled_items
