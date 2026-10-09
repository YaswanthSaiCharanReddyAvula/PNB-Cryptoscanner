"""
Phase 5 — Timeline Engine

Generates timeline windows for roadmap items based on priority and dependencies.
"""

from typing import List, Dict
from datetime import datetime, timedelta, timezone
from app.scanner.roadmap.models import RoadmapItem, RoadmapDependencyGraph, TimelineWindow, PriorityTier, EffortLevel

def generate_timeline(items: List[RoadmapItem], graph: RoadmapDependencyGraph) -> None:
    """
    Mutates the timeline field on items, assigning appropriate horizons.
    Depends on Priority and DAG.
    """
    # Create lookup map
    item_map = {item.roadmap_item_id: item for item in items}
    
    # Simple mapping from Priority to initial Window
    window_map = {
        PriorityTier.CRITICAL: TimelineWindow.IMMEDIATE,
        PriorityTier.HIGH: TimelineWindow.SHORT_TERM,
        PriorityTier.MEDIUM: TimelineWindow.MEDIUM_TERM,
        PriorityTier.LOW: TimelineWindow.LONG_TERM,
        PriorityTier.UNKNOWN: TimelineWindow.EXTENDED
    }
    
    days_map = {
        TimelineWindow.IMMEDIATE: 30,
        TimelineWindow.SHORT_TERM: 90,
        TimelineWindow.MEDIUM_TERM: 180,
        TimelineWindow.LONG_TERM: 365,
        TimelineWindow.EXTENDED: 730,
        TimelineWindow.UNKNOWN: None
    }

    # 1. Base assignment based on Priority
    for item in items:
        # Respect existing deadlines if they exist
        if item.timeline.deadline:
            days_until = (item.timeline.deadline - datetime.now(timezone.utc)).days
            if days_until <= 30:
                item.timeline.window = TimelineWindow.IMMEDIATE
            elif days_until <= 90:
                item.timeline.window = TimelineWindow.SHORT_TERM
            elif days_until <= 180:
                item.timeline.window = TimelineWindow.MEDIUM_TERM
            elif days_until <= 365:
                item.timeline.window = TimelineWindow.LONG_TERM
            else:
                item.timeline.window = TimelineWindow.EXTENDED
        else:
            item.timeline.window = window_map.get(item.tier, TimelineWindow.UNKNOWN)
            
        item.timeline.horizon_days = days_map.get(item.timeline.window)

    # 2. Dependency Shift
    # A task cannot be scheduled before its prerequisites.
    # We iterate through the DAG and shift downstream tasks if needed.
    
    # We use a topological sort approach to push delays forward.
    # Assuming topological_sort is performed or we can traverse cleanly.
    # If there are cycles, we skip shifting for safety.
    if not graph.has_cycles:
        from app.scanner.roadmap.dag import perform_topological_sort
        ordered_ids = perform_topological_sort(graph)
        
        window_order = [
            TimelineWindow.IMMEDIATE,
            TimelineWindow.SHORT_TERM,
            TimelineWindow.MEDIUM_TERM,
            TimelineWindow.LONG_TERM,
            TimelineWindow.EXTENDED,
            TimelineWindow.UNKNOWN
        ]
        
        for task_id in ordered_ids:
            item = item_map[task_id]
            node = graph.nodes[task_id]
            
            # Find the latest window among dependencies
            latest_dep_window_idx = -1
            for dep_id in node.blocked_by:
                dep_item = item_map[dep_id]
                dep_idx = window_order.index(dep_item.timeline.window) if dep_item.timeline.window in window_order else -1
                if dep_idx > latest_dep_window_idx:
                    latest_dep_window_idx = dep_idx
                    
            if latest_dep_window_idx != -1:
                current_idx = window_order.index(item.timeline.window) if item.timeline.window in window_order else -1
                # If dependency is later than current task, shift current task
                if latest_dep_window_idx > current_idx:
                    # Shift it to be at least the same window or next
                    # If it takes HIGH effort, maybe push it to the next window after the dependency
                    new_idx = latest_dep_window_idx
                    if item.effort == EffortLevel.HIGH and new_idx + 1 < len(window_order) - 1:
                        new_idx += 1
                        
                    item.timeline.window = window_order[new_idx]
                    item.timeline.horizon_days = days_map.get(item.timeline.window)
                    
                    if item.timeline.deadline:
                        item.timeline.deadline_conflict = True
                        item.explanation.append("Timeline shifted due to dependencies, conflicting with original deadline.")
