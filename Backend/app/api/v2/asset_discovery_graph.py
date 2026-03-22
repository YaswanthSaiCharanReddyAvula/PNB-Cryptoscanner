"""
QuantumShield — Asset Discovery Graph Endpoint

GET /api/asset-discovery → return graph {nodes, edges} from asset data
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import AssetDiscoveryGraph, GraphEdge, GraphNode

router = APIRouter(tags=["Asset Discovery"])


@router.get(
    "/asset-discovery",
    response_model=AssetDiscoveryGraph,
    summary="Return graph data representing discovered asset relationships",
)
async def asset_discovery_graph(
    session: AsyncSession = Depends(get_pg_session),
    _current_user: pg_models.User = Depends(get_current_user),
):
    """
    Build a graph from the assets table.
    Each asset is a node; shared owner groups form edges to represent relationships.
    """
    result = await session.execute(select(pg_models.Asset))
    assets = result.scalars().all()

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    # Group assets by owner to generate edges
    owner_groups: dict[str, list[str]] = {}
    for asset in assets:
        node_id = str(asset.id)
        nodes.append(GraphNode(
            id=node_id,
            label=asset.asset_name,
            type=asset.type or "unknown",
        ))
        owner = asset.owner or "unknown"
        owner_groups.setdefault(owner, []).append(node_id)

    # Connect assets that share the same owner
    for owner_nodes in owner_groups.values():
        if len(owner_nodes) > 1:
            primary = owner_nodes[0]
            for peer in owner_nodes[1:]:
                edges.append(GraphEdge(source=primary, target=peer))

    return AssetDiscoveryGraph(nodes=nodes, edges=edges)
