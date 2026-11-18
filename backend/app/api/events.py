"""API routes for ingesting security events and triggering simulation."""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import Event, Incident
from app.models.schemas import EventCreate, SimulateRequest
from app.orchestrator import Orchestrator
from simulator.generator import generate_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["events"])


@router.post("/events")
async def create_event(
    payload: EventCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Ingest a new raw security event and run the multi-agent response pipeline."""
    event = Event(
        event_type=payload.event_type,
        raw_content=payload.raw_content,
        source=payload.source,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    incident = Incident(event_id=event.id, status="analyzing")
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Run the pipeline immediately or via background task
    orchestrator = Orchestrator(db=db)
    await orchestrator.run_pipeline(event.id)

    return {
        "status": "processing",
        "event_id": event.id,
        "incident_id": incident.id,
    }


@router.post("/simulate")
async def simulate_attack(
    req: SimulateRequest = SimulateRequest(),
    db: Session = Depends(get_db),
):
    """Generate a realistic simulated security event and execute the pipeline."""
    generated = generate_event(event_type=req.event_type, scenario=req.scenario)

    event = Event(
        event_type=generated["event_type"],
        raw_content=generated["raw_content"],
        source=f"simulator:{generated.get('scenario', 'unknown')}",
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    orchestrator = Orchestrator(db=db)
    incident = await orchestrator.run_pipeline(event.id)

    return {
        "status": "completed",
        "incident_id": incident.id,
        "scenario": generated.get("scenario"),
        "is_malicious": generated.get("is_malicious"),
        "severity": incident.severity,
        "actions_count": len(incident.actions),
    }
