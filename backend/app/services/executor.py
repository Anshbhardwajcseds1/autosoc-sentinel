"""Simulated containment executor: executes and rolls back approved actions safely."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.db_models import ContainmentAction
from app.services.audit import AuditService

logger = logging.getLogger(__name__)


class SimulatedExecutor:
    """
    Executes containment actions in pure SIMULATION mode.
    NO network packets are dispatched to external firewalls or IAM services.
    Full audit trails and rollback states are updated.
    """

    def __init__(self, db: Session, audit_service: Optional[AuditService] = None):
        self.db = db
        self.audit = audit_service or AuditService(db_session=db)

    def execute_action(self, action: ContainmentAction, analyst_name: str = "analyst") -> dict:
        """Simulate execution of an approved containment action."""
        if action.status not in ("approved", "pending"):
            raise ValueError(f"Cannot execute action in status '{action.status}'")

        now = datetime.now(timezone.utc)
        action.status = "executed_simulated"
        action.executed_at = now
        action.approved_by = analyst_name
        if not action.approved_at:
            action.approved_at = now

        simulation_log = (
            f"[SIMULATED CONTAINMENT DISPATCH]\n"
            f"Timestamp: {now.isoformat()}\n"
            f"Action Type: {action.action_type}\n"
            f"Target: {action.target}\n"
            f"Command Executed (Dry-Run):\n{action.command_text}\n"
            f"Result: Success (Simulated: mock firewall/identity-provider rule registered)\n"
            f"Status: executed_simulated"
        )

        self.audit.log_action(
            actor="simulated_executor",
            action=f"executed_containment_{action.action_type}",
            incident_id=action.incident_id,
            details={
                "action_id": action.id,
                "action_type": action.action_type,
                "target": action.target,
                "command": action.command_text,
                "simulation": True,
            },
        )

        self.db.commit()
        self.db.refresh(action)

        return {
            "status": "executed_simulated",
            "executed_at": now.isoformat(),
            "simulation_log": simulation_log,
        }

    def rollback_action(self, action: ContainmentAction, analyst_name: str = "analyst") -> dict:
        """Simulate rollback of an executed containment action."""
        if action.status != "executed_simulated":
            raise ValueError(f"Cannot rollback action in status '{action.status}'. Must be 'executed_simulated'.")

        if not action.reversible:
            raise ValueError(f"Action '{action.id}' is marked as non-reversible.")

        now = datetime.now(timezone.utc)
        action.status = "rolled_back"

        rollback_log = (
            f"[SIMULATED CONTAINMENT ROLLBACK]\n"
            f"Timestamp: {now.isoformat()}\n"
            f"Action Type: {action.action_type}\n"
            f"Target: {action.target}\n"
            f"Rollback Command (Dry-Run):\n{action.rollback_command}\n"
            f"Result: Success (Simulated: rule removed / account restored)\n"
            f"Status: rolled_back"
        )

        self.audit.log_action(
            actor="simulated_executor",
            action=f"rollback_containment_{action.action_type}",
            incident_id=action.incident_id,
            details={
                "action_id": action.id,
                "action_type": action.action_type,
                "target": action.target,
                "rollback_command": action.rollback_command,
                "analyst": analyst_name,
                "simulation": True,
            },
        )

        self.db.commit()
        self.db.refresh(action)

        return {
            "status": "rolled_back",
            "rolled_back_at": now.isoformat(),
            "simulation_log": rollback_log,
        }
