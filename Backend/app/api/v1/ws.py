import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.ws_manager import manager
from app.db.connection import get_database
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Stage name → friendly label mapping
_STAGE_LABELS = {
    "Asset Discovery": "Asset Discovery",
    "TLS Scanning":    "TLS Scanning",
    "Crypto Analysis": "Crypto Analysis",
    "Quantum Risk":    "Quantum Risk Scoring",
    "CBOM Generation": "CBOM Generation",
    "Recommendations": "PQC Recommendations",
    "HTTP Headers":    "HTTP Security Headers",
    "CVE Mapping":     "CVE / Attack Mapping",
}


@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint that polls MongoDB every 2 s and pushes structured
    stage/progress JSON to the connected frontend client.

    Message format (running):
        {"stage": "Asset Discovery", "progress": 20, "status": "running",
         "message": "Scanning subdomains..."}

    Message format (completed):
        {"stage": "Complete", "progress": 100, "status": "completed",
         "scan_id": "...", "domain": "..."}
    """
    await manager.connect(websocket, scan_id)
    logger.info("WS client connected for scan: %s", scan_id)

    db = get_database()
    collection = db["scans"]

    try:
        while True:
            try:
                doc = await collection.find_one({"scan_id": scan_id}, {"_id": 0})
            except Exception as db_err:
                logger.warning("WS DB poll error for %s: %s", scan_id, db_err)
                doc = None

            if doc:
                db_status = doc.get("status", "pending")
                stage     = doc.get("current_stage", "Initialising")
                progress  = doc.get("progress", 0)
                domain    = doc.get("domain", "")

                if db_status == "completed":
                    await websocket.send_text(json.dumps({
                        "stage":    "Complete",
                        "progress": 100,
                        "status":   "completed",
                        "scan_id":  scan_id,
                        "domain":   domain,
                        "message":  "Scan completed successfully.",
                    }))
                    break

                elif db_status == "failed":
                    await websocket.send_text(json.dumps({
                        "stage":    stage,
                        "progress": progress,
                        "status":   "failed",
                        "scan_id":  scan_id,
                        "message":  doc.get("error", "Scan failed."),
                    }))
                    break

                else:
                    label = _STAGE_LABELS.get(stage, stage)
                    await websocket.send_text(json.dumps({
                        "stage":    label,
                        "progress": progress,
                        "status":   "running",
                        "message":  f"{label}…",
                    }))

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        logger.info("WS client disconnected from scan: %s", scan_id)
    except Exception as exc:
        logger.error("WS error for scan %s: %s", scan_id, exc)
    finally:
        manager.disconnect(websocket, scan_id)

