from fastapi import APIRouter

# All router modules share a single APIRouter via `from .common import *`.
# Importing each module triggers its @router decorators to register on
# that shared object.  We include it exactly once to avoid duplicate routes.
from .routers import scan, dashboard, assets, crypto_cbom, admin_governance, auth, system  # noqa: F401  — side-effect imports
from .routers.common import router as _shared_router

main_router = APIRouter()

main_router.include_router(_shared_router)
