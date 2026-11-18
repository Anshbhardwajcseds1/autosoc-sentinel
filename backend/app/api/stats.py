"""API routes for SOC dashboard metrics and analytics."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import ContainmentAction, Incident
from app.models.schemas import StatsResponse

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Calculate real-time operational statistics for the SOC dashboard."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_incidents = db.query(Incident).count()
    incidents_today = (
        db.query(Incident)
        .filter(Incident.created_at >= today_start)
        .count()
    )
    open_incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(["analyzing", "awaiting_review"]))
        .count()
    )

    critical_count = db.query(Incident).filter(Incident.severity == "Critical").count()
    high_count = db.query(Incident).filter(Incident.severity == "High").count()
    medium_count = db.query(Incident).filter(Incident.severity == "Medium").count()
    low_count = db.query(Incident).filter(Incident.severity == "Low").count()

    total_actions = db.query(ContainmentAction).count()
    approved_actions = (
        db.query(ContainmentAction)
        .filter(ContainmentAction.status.in_(["approved", "executed_simulated"]))
        .count()
    )
    rejected_actions = (
        db.query(ContainmentAction)
        .filter(ContainmentAction.status == "rejected")
        .count()
    )
    pending_actions = (
        db.query(ContainmentAction)
        .filter(ContainmentAction.status == "pending")
        .count()
    )

    reviewed_actions = approved_actions + rejected_actions
    approval_rate = (
        round((approved_actions / reviewed_actions) * 100.0, 1)
        if reviewed_actions > 0
        else 0.0
    )

    # Calculate MTTR (mean time from incident created to first action executed)
    executed_actions = (
        db.query(ContainmentAction)
        .join(Incident)
        .filter(ContainmentAction.executed_at != None)
        .all()
    )

    mttr_seconds = None
    if executed_actions:
        deltas = []
        for a in executed_actions:
            if a.executed_at and a.incident and a.incident.created_at:
                delta = (
                    a.executed_at.replace(tzinfo=timezone.utc)
                    - a.incident.created_at.replace(tzinfo=timezone.utc)
                ).total_seconds()
                if delta >= 0:
                    deltas.append(delta)
        if deltas:
            mttr_seconds = round(sum(deltas) / len(deltas), 1)

    return StatsResponse(
        incidents_today=incidents_today,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        critical_incidents=critical_count,
        high_incidents=high_count,
        medium_incidents=medium_count,
        low_incidents=low_count,
        total_actions=total_actions,
        approved_actions=approved_actions,
        rejected_actions=rejected_actions,
        pending_actions=pending_actions,
        approval_rate=approval_rate,
        mean_time_to_respond_seconds=mttr_seconds,
    )
