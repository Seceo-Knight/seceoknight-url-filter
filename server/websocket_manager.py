"""
websocket_manager.py
SecEoKnight — manages WebSocket connections from the dashboard.

Usage:
    ws_manager = WebSocketManager()

    # In FastAPI route:
    await ws_manager.connect(websocket)

    # To push an alert to all connected dashboards:
    await ws_manager.broadcast(alert_dict)
"""

import asyncio
import json
from typing import List
from fastapi import WebSocket


class WebSocketManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"[WS] Dashboard connected — total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        print(f"[WS] Dashboard disconnected — total: {len(self.active)}")

    async def broadcast(self, data: dict):
        """Send alert to every connected dashboard client."""
        if not self.active:
            return
        message = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_to(self, ws: WebSocket, data: dict):
        """Send a message to a single client."""
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            self.disconnect(ws)


# Singleton — imported by unified_server.py
ws_manager = WebSocketManager()
