"""
QuantumShield — API v2 Aggregate Router

Mounts all sub-routers under the /api prefix.
"""

from fastapi import APIRouter

from app.api.v2 import (
    auth,
    users,
    dashboard,
    assets,
    nameservers,
    crypto,
    asset_inventory,
    asset_discovery_graph,
    cbom,
    pqc,
    cyber_rating,
    reports,
)

api_router = APIRouter()

# Auth
api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(users.router)

# Dashboard
api_router.include_router(dashboard.router)

# Assets
api_router.include_router(assets.router)
api_router.include_router(nameservers.router)
api_router.include_router(asset_inventory.router)
api_router.include_router(asset_discovery_graph.router)

# Crypto & Security
api_router.include_router(crypto.router)
api_router.include_router(cbom.router)
api_router.include_router(pqc.router)
api_router.include_router(cyber_rating.router)

# Reporting
api_router.include_router(reports.router)
