from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.ws_manager import manager
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    logger.info(f"Client connected to scan WebSocket: {scan_id}")
    try:
        while True:
            # We don't expect messages from the client for now, but we need to keep the connection alive
            # and detect when they disconnect.
            data = await websocket.receive_text()
            # If we need to handle client commands, we can do it here.
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
        logger.info(f"Client disconnected from scan WebSocket: {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        manager.disconnect(websocket, scan_id)
