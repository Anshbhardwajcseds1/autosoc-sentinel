"""Audit service: Append-only audit trail for all agent and human actions."""

from __future__ import annotations

import logging
from typing import Any, Optional
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.db_models import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Provides append-only immutable audit logging."""

    def __init__(self, db_session: Optional[Session] = None):
        self.db = db_session

    def _get_db(self) -> Session:
        if self.db is not None:
            return self.db
        return SessionLocal()

    def log_action(
        self,
        actor: str,
        action: str,
        incident_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditLog:
        """Create and persist an immutable audit log entry."""
        db = self._get_db()
        try:
            entry = AuditLog(
                actor=actor,
                action=action,
                incident_id=incident_id,
                details=details or {},
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            logger.info("AUDIT | actor=%s | action=%s | incident=%s", actor, action, incident_id)
            return entry
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)
            db.rollback()
            raise
        finally:
            if self.db is None:
                db.close()
