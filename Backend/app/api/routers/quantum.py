from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.db.connection import get_db

router = APIRouter(prefix="/quantum", tags=["Quantum Risk"])

@router.get("/risk", response_model=List[Dict[str, Any]])
async def get_all_quantum_risk(
    scan_id: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    query = {}
    if scan_id:
        query["scan_id"] = scan_id
    cursor = db.quantum_assessments.find(query, {"_id": 0})
    return await cursor.to_list(length=1000)

@router.get("/assets", response_model=List[Dict[str, Any]])
async def get_quantum_assets(
    scan_id: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    query = {}
    if scan_id:
        query["scan_id"] = scan_id
    cursor = db.quantum_assessments.find(query, {"_id": 0, "asset_id": 1, "overall_quantum_risk": 1, "risk_tier": 1, "hndl": 1, "mosca": 1})
    return await cursor.to_list(length=1000)

@router.get("/assets/{asset_id}", response_model=List[Dict[str, Any]])
async def get_quantum_asset_details(
    asset_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    cursor = db.quantum_assessments.find({"asset_id": asset_id}, {"_id": 0})
    assessments = await cursor.to_list(length=1000)
    if not assessments:
        raise HTTPException(status_code=404, detail="No quantum assessments found for this asset")
    return assessments

@router.get("/hndl", response_model=List[Dict[str, Any]])
async def get_hndl_exposure(
    scan_id: Optional[str] = None,
    min_exposure: float = 0.0,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    query = {"hndl.exposure": {"$gt": min_exposure}}
    if scan_id:
        query["scan_id"] = scan_id
    cursor = db.quantum_assessments.find(query, {"_id": 0, "asset_id": 1, "subject_id": 1, "hndl": 1})
    return await cursor.to_list(length=1000)

@router.get("/mosca", response_model=List[Dict[str, Any]])
async def get_mosca_urgency(
    scan_id: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_db)
):
    query = {"mosca.status": {"$in": ["CRITICAL_URGENCY", "MIGRATION_REQUIRED"]}}
    if scan_id:
        query["scan_id"] = scan_id
    cursor = db.quantum_assessments.find(query, {"_id": 0, "asset_id": 1, "subject_id": 1, "mosca": 1, "timeline": 1})
    return await cursor.to_list(length=1000)

@router.get("/scenarios")
async def get_quantum_scenarios():
    return {
        "optimistic": {"Tq": {"value": 20.0, "unit": "years"}},
        "baseline": {"Tq": {"value": 15.0, "unit": "years"}},
        "aggressive": {"Tq": {"value": 10.0, "unit": "years"}},
    }

@router.get("/model")
async def get_quantum_model_info():
    return {
        "risk_model_version": "4.0.0",
        "taxonomy_version": "2026.1",
        "equation": "Mosca Margin = Tm + Tc - Tq"
    }
