"""
Phase 5 — Dependency Graph Engine

Detects cycles, performs topological ordering, and identifies parallelizable tasks.
"""

from typing import List, Dict, Set
from app.scanner.roadmap.models import RoadmapItem, RoadmapDependencyGraph, DependencyNode, TaskStatus

def build_dependency_graph(items: List[RoadmapItem]) -> RoadmapDependencyGraph:
    """Builds a verified DAG from the roadmap items."""
    graph = RoadmapDependencyGraph()
    
    # 1. Initialize nodes and bidirectional edges
    item_map = {item.roadmap_item_id: item for item in items}
    
    for item in items:
        node = DependencyNode(
            task_id=item.roadmap_item_id,
            status=item.status,
            blocked_by=[],
            blocks=[]
        )
        graph.nodes[item.roadmap_item_id] = node

    for item in items:
        for dep_id in item.dependencies + item.prerequisites:
            if dep_id in graph.nodes:
                # Add edges
                if dep_id not in graph.nodes[item.roadmap_item_id].blocked_by:
                    graph.nodes[item.roadmap_item_id].blocked_by.append(dep_id)
                if item.roadmap_item_id not in graph.nodes[dep_id].blocks:
                    graph.nodes[dep_id].blocks.append(item.roadmap_item_id)
                    
    # 2. Cycle Detection
    def has_cycle(v: str, visited: Set[str], rec_stack: Set[str]) -> bool:
        visited.add(v)
        rec_stack.add(v)
        for neighbor in graph.nodes[v].blocks:
            if neighbor not in visited:
                if has_cycle(neighbor, visited, rec_stack):
                    return True
            elif neighbor in rec_stack:
                return True
        rec_stack.remove(v)
        return False

    visited = set()
    rec_stack = set()
    for node_id in graph.nodes:
        if node_id not in visited:
            if has_cycle(node_id, visited, rec_stack):
                graph.has_cycles = True
                break

    # If cycles exist, we must break them or reject the graph.
    # For now, we just flag it. The calling engine might clear dependencies to recover.

    # 3. Determine Execution State (Ready vs Blocked)
    for node_id, node in graph.nodes.items():
        if node.status in (TaskStatus.COMPLETED, TaskStatus.WAIVED, TaskStatus.CANCELLED):
            continue
            
        is_ready = True
        for dep_id in node.blocked_by:
            dep_node = graph.nodes.get(dep_id)
            if dep_node and dep_node.status not in (TaskStatus.COMPLETED, TaskStatus.WAIVED, TaskStatus.CANCELLED):
                is_ready = False
                break
                
        if is_ready:
            graph.ready_tasks.append(node_id)
        else:
            graph.blocked_tasks.append(node_id)
            
    # 4. Group Parallel Tasks
    # Tasks in ready state that share the same asset can be done together or grouped.
    # For now, we group ready tasks by their Track and Asset.
    parallel_map: Dict[str, List[str]] = {}
    for node_id in graph.ready_tasks:
        item = item_map[node_id]
        if not item.asset_ids:
            continue
        # Group key: track + first asset (simplified)
        group_key = f"{item.track.value}_{item.asset_ids[0]}"
        parallel_map.setdefault(group_key, []).append(node_id)
        
    for k, v in parallel_map.items():
        if len(v) > 1:
            graph.parallel_groups[k] = v

    return graph


def perform_topological_sort(graph: RoadmapDependencyGraph) -> List[str]:
    """Returns task IDs in execution order."""
    if graph.has_cycles:
        return [] # Cannot topologically sort a cyclic graph
        
    in_degree = {node_id: len(node.blocked_by) for node_id, node in graph.nodes.items()}
    queue = [node_id for node_id, degree in in_degree.items() if degree == 0]
    
    ordered = []
    while queue:
        # Sort queue to ensure determinism
        queue.sort() 
        current = queue.pop(0)
        ordered.append(current)
        
        for neighbor in graph.nodes[current].blocks:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                
    return ordered
