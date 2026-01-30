"""
NetSpecter WebSocket Handler

Real-time progress updates via WebSocket connections.
"""

import asyncio
from typing import Callable

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["websocket"])


# =============================================================================
# Connection Manager
# =============================================================================


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.

    Allows subscribing to specific analysis IDs for progress updates.
    """

    def __init__(self) -> None:
        # Map of analysis_id -> list of connected websockets
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, analysis_id: str) -> None:
        """Accept and register a WebSocket connection for an analysis."""
        await websocket.accept()

        if analysis_id not in self._connections:
            self._connections[analysis_id] = []

        self._connections[analysis_id].append(websocket)

        logger.info(
            "websocket_connected",
            analysis_id=analysis_id,
            total_connections=len(self._connections[analysis_id]),
        )

    def disconnect(self, websocket: WebSocket, analysis_id: str) -> None:
        """Remove a WebSocket connection."""
        if analysis_id in self._connections:
            if websocket in self._connections[analysis_id]:
                self._connections[analysis_id].remove(websocket)

            # Clean up empty lists
            if not self._connections[analysis_id]:
                del self._connections[analysis_id]

        logger.info("websocket_disconnected", analysis_id=analysis_id)

    async def broadcast(self, analysis_id: str, message: dict) -> None:
        """Send a message to all connections subscribed to an analysis."""
        if analysis_id not in self._connections:
            return

        disconnected = []

        for websocket in self._connections[analysis_id]:
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected sockets
        for ws in disconnected:
            self.disconnect(ws, analysis_id)

    def get_broadcast_callback(self, analysis_id: str) -> Callable:
        """
        Get a callback function for broadcasting progress updates.

        This can be passed to the parser for real-time progress streaming.
        """

        async def broadcast_progress(progress: dict) -> None:
            await self.broadcast(analysis_id, {"type": "progress", "data": progress})

        return broadcast_progress


# Global connection manager instance
manager = ConnectionManager()


# =============================================================================
# WebSocket Endpoints
# =============================================================================


@router.websocket("/ws/analysis/{analysis_id}")
async def analysis_websocket(websocket: WebSocket, analysis_id: str) -> None:
    """
    WebSocket endpoint for real-time analysis progress updates.

    Connect to receive progress updates for a specific analysis.

    Message Types:
    - progress: Parsing/analysis progress update
    - phase: Analysis phase change
    - finding: New finding detected
    - complete: Analysis complete
    - error: Error occurred
    """
    await manager.connect(websocket, analysis_id)

    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "analysis_id": analysis_id,
            "message": "Connected to analysis progress stream",
        })

        # Keep connection alive and handle any client messages
        while True:
            try:
                # Wait for client messages (ping/pong, etc.)
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0,  # Send ping every 30 seconds
                )

                # Handle ping
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})

            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info("websocket_client_disconnected", analysis_id=analysis_id)
    except Exception as e:
        logger.error(
            "websocket_error",
            analysis_id=analysis_id,
            error=str(e),
        )
    finally:
        manager.disconnect(websocket, analysis_id)


# =============================================================================
# Helper Functions
# =============================================================================


async def send_progress_update(
    analysis_id: str,
    status: str,
    phase: str,
    progress: float,
    packets_processed: int,
    total_packets: int | None = None,
    elapsed_seconds: float = 0.0,
) -> None:
    """
    Send a progress update to all connected clients for an analysis.

    This is called from the analysis pipeline to stream updates.
    """
    await manager.broadcast(
        analysis_id,
        {
            "type": "progress",
            "data": {
                "status": status,
                "phase": phase,
                "progress": progress,
                "packets_processed": packets_processed,
                "total_packets": total_packets,
                "elapsed_seconds": elapsed_seconds,
            },
        },
    )


async def send_phase_change(analysis_id: str, phase: str, description: str) -> None:
    """Send a phase change notification."""
    await manager.broadcast(
        analysis_id,
        {
            "type": "phase",
            "data": {
                "phase": phase,
                "description": description,
            },
        },
    )


async def send_finding(analysis_id: str, finding: dict) -> None:
    """Send a new finding notification."""
    await manager.broadcast(
        analysis_id,
        {
            "type": "finding",
            "data": finding,
        },
    )


async def send_complete(analysis_id: str, summary: dict) -> None:
    """Send analysis complete notification."""
    await manager.broadcast(
        analysis_id,
        {
            "type": "complete",
            "data": summary,
        },
    )


async def send_error(analysis_id: str, error: str) -> None:
    """Send error notification."""
    await manager.broadcast(
        analysis_id,
        {
            "type": "error",
            "data": {"error": error},
        },
    )
