"""FastAPI application entry point for AutoSOC Sentinel."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.actions import router as actions_router
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.stats import router as stats_router
from app.api.websocket import ws_manager
from app.config import get_settings
from app.database import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    logger.info("Initializing database schema...")
    init_db()
    logger.info(
        "AutoSOC Sentinel active. Mock mode: %s | LLM mock: %s",
        settings.mock_mode,
        settings.llm_mock_mode,
    )
    yield
    logger.info("AutoSOC Sentinel shutting down.")


app = FastAPI(
    title="AutoSOC Sentinel",
    description="Autonomous incident response system with human-in-the-loop approval",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(actions_router)
app.include_router(stats_router)


@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """Real-time event stream for frontend SOC dashboard."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket exception: %s", e)
        ws_manager.disconnect(websocket)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "version": "1.0.0",
        "mock_mode": settings.mock_mode,
        "llm_mock_mode": settings.llm_mock_mode,
    }
