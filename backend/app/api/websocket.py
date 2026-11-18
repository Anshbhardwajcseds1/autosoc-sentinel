"""WebSocket connection manager for real-time dashboard events."""

from __future__ import annotations

import json
import logging
from typing import Any, List
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket client connections and broadcasting."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected (%d active)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected (%d active)", len(self.active_connections))

    async def broadcast(self, event_type: str, incident_id: str, data: dict[str, Any]):
        """Broadcast an event to all active WebSocket clients."""
        payload = {
            "event_type": event_type,
            "incident_id": incident_id,
            "data": data,
        }
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception as e:
                logger.warning("Failed to send WebSocket message: %s", e)
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()
