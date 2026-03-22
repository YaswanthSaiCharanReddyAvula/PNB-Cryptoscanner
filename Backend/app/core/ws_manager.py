from typing import Dict, List, Any
from fastapi import WebSocket
import json
import asyncio

class ConnectionManager:
    """
    Manages active WebSocket connections for real-time scan updates.
    Connections are grouped by scan_id to allow multi-client monitoring of the same scan.
    """
    def __init__(self):
        # scan_id -> list of active websockets
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: Any, scan_id: str):
        """Broadcasts a JSON-serializable message to all clients monitoring a specific scan."""
        if scan_id in self.active_connections:
            payload = json.dumps(message)
            # Create a copy of the list to avoid issues with concurrent disconnects
            for connection in self.active_connections[scan_id][:]:
                try:
                    await connection.send_text(payload)
                except Exception:
                    # Connection might be closed, handled in disconnect usually but safely ignore here
                    pass

manager = ConnectionManager()
