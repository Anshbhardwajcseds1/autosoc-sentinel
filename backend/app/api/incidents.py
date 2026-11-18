"""API routes for listing and inspecting incident details."""

from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.db_models import AuditLog, Incident
from app.models.schemas import (
    AuditLogResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
    Severity,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=List[IncidentSummaryResponse])
def list_incidents(
    severity: Optional[Severity] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Retrieve queue of incidents sorted by creation date descending."""
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)

    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()

    results = []
    for inc in incidents:
        pending_count = sum(1 for a in inc.actions if a.status == "pending")
        results.append(
            IncidentSummaryResponse(
                id=inc.id,
                event_id=inc.event_id,
                status=inc.status,
                severity=inc.severity,
                summary=inc.summary,
                incident_type=inc.incident_type,
                confidence=inc.confidence,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                ioc_count=len(inc.iocs),
                action_count=len(inc.actions),
                pending_action_count=pending_count,
            )
        )
    return results


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Get complete details, IOCs, intelligence, actions, timeline, and audit logs."""
    incident = (
        db.query(Incident)
        .options(
            joinedload(Incident.event),
            joinedload(Incident.iocs),
            joinedload(Incident.actions),
            joinedload(Incident.agent_steps),
            joinedload(Incident.audit_logs),
        )
        .filter(Incident.id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch threat intel results for all IOCs of this incident
    all_intel = []
    for ioc in incident.iocs:
        all_intel.extend(ioc.threat_intel_results)

    # Sort agent steps by timestamp
    incident.agent_steps.sort(key=lambda s: s.timestamp)
    # Sort audit logs by timestamp descending
    incident.audit_logs.sort(key=lambda a: a.timestamp, reverse=True)

    return IncidentDetailResponse(
        id=incident.id,
        event_id=incident.event_id,
        status=incident.status,
        severity=incident.severity,
        summary=incident.summary,
        incident_type=incident.incident_type,
        confidence=incident.confidence,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        event=incident.event,
        iocs=incident.iocs,
        threat_intel_results=all_intel,
        actions=incident.actions,
        agent_steps=incident.agent_steps,
        audit_logs=incident.audit_logs,
    )


@router.get("/{incident_id}/audit-log", response_model=List[AuditLogResponse])
def get_incident_audit_log(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Get immutable audit trail specifically for an incident."""
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.incident_id == incident_id)
        .order_by(AuditLog.timestamp.desc())
        .all()
    )
    return logs
