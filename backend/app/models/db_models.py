"""SQLAlchemy ORM models for AutoSOC Sentinel."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Event ────────────────────────────────────────────────────

class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_type = Column(
        Enum("phishing_email", "auth_log", "malware_alert", name="event_type_enum"),
        nullable=False,
    )
    raw_content = Column(Text, nullable=False)
    source = Column(String(255), default="simulator")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    incident = relationship("Incident", back_populates="event", uselist=False)


# ── Incident ─────────────────────────────────────────────────

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(36), ForeignKey("events.id"), nullable=False, unique=True)
    status = Column(
        Enum("analyzing", "awaiting_review", "resolved", "escalated", name="incident_status_enum"),
        default="analyzing",
        nullable=False,
    )
    severity = Column(
        Enum("Low", "Medium", "High", "Critical", name="severity_enum"),
        nullable=True,
    )
    summary = Column(Text, nullable=True)
    incident_type = Column(String(100), nullable=True)
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    event = relationship("Event", back_populates="incident")
    iocs = relationship("IOC", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("ContainmentAction", back_populates="incident", cascade="all, delete-orphan")
    agent_steps = relationship("AgentStep", back_populates="incident", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="incident", cascade="all, delete-orphan")


# ── IOC (Indicator of Compromise) ────────────────────────────

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    ioc_type = Column(
        Enum("ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256", "username", name="ioc_type_enum"),
        nullable=False,
    )
    value = Column(String(1024), nullable=False)
    context = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="iocs")
    threat_intel_results = relationship("ThreatIntelResult", back_populates="ioc", cascade="all, delete-orphan")


# ── Threat Intel Result ──────────────────────────────────────

class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id = Column(String(36), primary_key=True, default=_uuid)
    ioc_id = Column(String(36), ForeignKey("iocs.id"), nullable=False)
    source = Column(
        Enum("virustotal", "abuseipdb", "mock", name="intel_source_enum"),
        nullable=False,
    )
    reputation_score = Column(Float, nullable=False)
    malicious = Column(Boolean, default=False)
    raw_response = Column(JSON, nullable=True)
    cached = Column(Boolean, default=False)
    queried_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    ioc = relationship("IOC", back_populates="threat_intel_results")


# ── Containment Action ───────────────────────────────────────

class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    action_type = Column(
        Enum(
            "block_ip", "block_domain", "quarantine_email",
            "lock_account", "force_password_reset", "revoke_sessions",
            name="action_type_enum",
        ),
        nullable=False,
    )
    target = Column(String(1024), nullable=False)
    rationale = Column(Text, nullable=True)
    risk_level = Column(
        Enum("low", "medium", "high", name="risk_level_enum"),
        default="medium",
        nullable=False,
    )
    reversible = Column(Boolean, default=True)
    command_text = Column(Text, nullable=True)
    rollback_command = Column(Text, nullable=True)
    status = Column(
        Enum(
            "pending", "approved", "rejected", "executed_simulated", "rolled_back",
            name="action_status_enum",
        ),
        default="pending",
        nullable=False,
    )
    analyst_comment = Column(Text, nullable=True)
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    is_recommended = Column(Boolean, default=False)
    warning = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="actions")


# ── Agent Step (reasoning timeline) ──────────────────────────

class AgentStep(Base):
    __tablename__ = "agent_steps"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    agent_name = Column(String(100), nullable=False)
    input_summary = Column(Text, nullable=True)
    output_summary = Column(Text, nullable=True)
    reasoning = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    status = Column(
        Enum("success", "error", name="step_status_enum"),
        default="success",
        nullable=False,
    )
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    incident = relationship("Incident", back_populates="agent_steps")


# ── Audit Log ────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    actor = Column(String(255), nullable=False)
    action = Column(String(255), nullable=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    incident = relationship("Incident", back_populates="audit_logs")


# ── Threat Intel Cache ───────────────────────────────────────

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String(36), primary_key=True, default=_uuid)
    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(String(1024), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    response_data = Column(JSON, nullable=False)
    reputation_score = Column(Float, nullable=False)
    malicious = Column(Boolean, default=False)
    cached_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    ttl_seconds = Column(Integer, default=86400)
