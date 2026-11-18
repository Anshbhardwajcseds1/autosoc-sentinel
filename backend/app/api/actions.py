"""API routes for human analyst approval, rejection, and simulation execution of containment actions."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.websocket import ws_manager
from app.database import get_db
from app.models.db_models import ContainmentAction, Incident
from app.models.schemas import ActionApproval, ContainmentActionResponse
from app.services.audit import AuditService
from app.services.executor import SimulatedExecutor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents/{incident_id}/actions", tags=["actions"])


@router.post("/{action_id}/approve")
async def approve_action(
    incident_id: str,
    action_id: str,
    payload: ActionApproval = ActionApproval(),
    db: Session = Depends(get_db),
):
    """Approve a containment action and trigger the SIMULATED executor."""
    action = (
        db.query(ContainmentAction)
        .filter(
            ContainmentAction.id == action_id,
            ContainmentAction.incident_id == incident_id,
        )
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail="Containment action not found")

    if action.status not in ("pending", "rejected"):
        raise HTTPException(
            status_code=400,
            detail=f"Action is already in status '{action.status}' and cannot be approved",
        )

    action.analyst_comment = payload.analyst_comment
    action.approved_by = payload.approved_by
    action.approved_at = datetime.now(timezone.utc)
    action.status = "approved"

    audit = AuditService(db_session=db)
    audit.log_action(
        actor=payload.approved_by,
        action="analyst_approved_action",
        incident_id=incident_id,
        details={
            "action_id": action.id,
            "action_type": action.action_type,
            "target": action.target,
            "comment": payload.analyst_comment,
        },
    )

    # Automatically dispatch to simulated executor
    executor = SimulatedExecutor(db=db, audit_service=audit)
    exec_result = executor.execute_action(action, analyst_name=payload.approved_by)

    # Check if all actions are reviewed; if so, update incident status
    remaining = (
        db.query(ContainmentAction)
        .filter(
            ContainmentAction.incident_id == incident_id,
            ContainmentAction.status == "pending",
        )
        .count()
    )
    if remaining == 0:
        inc = db.query(Incident).filter(Incident.id == incident_id).first()
        if inc:
            inc.status = "resolved"
            db.commit()

    await ws_manager.broadcast(
        "action_updated",
        incident_id,
        {
            "action_id": action.id,
            "status": action.status,
            "simulation_result": exec_result,
        },
    )

    return {
        "status": "success",
        "action_id": action.id,
        "action_status": action.status,
        "execution": exec_result,
    }


@router.post("/{action_id}/reject")
async def reject_action(
    incident_id: str,
    action_id: str,
    payload: ActionApproval = ActionApproval(),
    db: Session = Depends(get_db),
):
    """Reject a proposed containment action with an optional comment."""
    action = (
        db.query(ContainmentAction)
        .filter(
            ContainmentAction.id == action_id,
            ContainmentAction.incident_id == incident_id,
        )
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail="Containment action not found")

    action.status = "rejected"
    action.analyst_comment = payload.analyst_comment
    action.approved_by = payload.approved_by

    audit = AuditService(db_session=db)
    audit.log_action(
        actor=payload.approved_by,
        action="analyst_rejected_action",
        incident_id=incident_id,
        details={
            "action_id": action.id,
            "action_type": action.action_type,
            "target": action.target,
            "comment": payload.analyst_comment,
        },
    )

    db.commit()
    db.refresh(action)

    await ws_manager.broadcast(
        "action_updated",
        incident_id,
        {"action_id": action.id, "status": "rejected"},
    )

    return {"status": "success", "action_id": action.id, "action_status": "rejected"}


@router.post("/approve-recommended")
async def approve_all_recommended(
    incident_id: str,
    payload: ActionApproval = ActionApproval(),
    db: Session = Depends(get_db),
):
    """One-click batch approval of all recommended actions for an incident."""
    actions = (
        db.query(ContainmentAction)
        .filter(
            ContainmentAction.incident_id == incident_id,
            ContainmentAction.is_recommended == True,
            ContainmentAction.status == "pending",
        )
        .all()
    )

    if not actions:
        return {"status": "success", "approved_count": 0, "message": "No pending recommended actions."}

    audit = AuditService(db_session=db)
    executor = SimulatedExecutor(db=db, audit_service=audit)
    executed_results = []

    for action in actions:
        action.analyst_comment = payload.analyst_comment or "Batch-approved recommended actions"
        action.approved_by = payload.approved_by
        res = executor.execute_action(action, analyst_name=payload.approved_by)
        executed_results.append({"action_id": action.id, "result": res})

    db.commit()

    await ws_manager.broadcast(
        "action_updated",
        incident_id,
        {"batch": True, "count": len(executed_results)},
    )

    return {
        "status": "success",
        "approved_count": len(executed_results),
        "actions": executed_results,
    }


@router.post("/{action_id}/rollback")
async def rollback_action(
    incident_id: str,
    action_id: str,
    payload: ActionApproval = ActionApproval(),
    db: Session = Depends(get_db),
):
    """Roll back a simulated-executed containment action."""
    action = (
        db.query(ContainmentAction)
        .filter(
            ContainmentAction.id == action_id,
            ContainmentAction.incident_id == incident_id,
        )
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail="Containment action not found")

    audit = AuditService(db_session=db)
    executor = SimulatedExecutor(db=db, audit_service=audit)

    try:
        rollback_res = executor.rollback_action(action, analyst_name=payload.approved_by)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    await ws_manager.broadcast(
        "action_updated",
        incident_id,
        {"action_id": action.id, "status": "rolled_back", "rollback": rollback_res},
    )

    return {
        "status": "success",
        "action_id": action.id,
        "action_status": "rolled_back",
        "rollback": rollback_res,
    }
