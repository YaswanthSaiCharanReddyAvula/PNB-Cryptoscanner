import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.ws_manager import enrich_ws_payload, manager
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
    Polls MongoDB every 2s and pushes stage/progress (backup to pipeline broadcasts).

    Frames include type, scan_id, ts (UTC) for parity with pipeline ws_manager.broadcast:
        {"type": "status", "stage": "...", "progress": N, "status": "running",
         "message": "...", "scan_id": "...", "ts": "..."}
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
                    await websocket.send_text(
                        json.dumps(
                            enrich_ws_payload(
                                {
                                    "type": "status",
                                    "stage": "Complete",
                                    "progress": 100,
                                    "status": "completed",
                                    "domain": domain,
                                    "message": "Scan completed successfully.",
                                },
                                scan_id,
                            )
                        )
                    )
                    break

                elif db_status == "failed":
                    await websocket.send_text(
                        json.dumps(
                            enrich_ws_payload(
                                {
                                    "type": "status",
                                    "stage": stage,
                                    "progress": progress,
                                    "status": "failed",
                                    "message": doc.get("error", "Scan failed."),
                                },
                                scan_id,
                            )
                        )
                    )
                    break

                else:
                    label = _STAGE_LABELS.get(stage, stage)
                    await websocket.send_text(
                        json.dumps(
                            enrich_ws_payload(
                                {
                                    "type": "status",
                                    "stage": label,
                                    "progress": progress,
                                    "status": "running",
                                    "message": f"{label}…",
                                },
                                scan_id,
                            )
                        )
                    )

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        logger.info("WS client disconnected from scan: %s", scan_id)
    except Exception as exc:
        logger.error("WS error for scan %s: %s", scan_id, exc)
    finally:
        manager.disconnect(websocket, scan_id)

