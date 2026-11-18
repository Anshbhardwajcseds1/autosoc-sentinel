"""Pydantic v2 schemas for API request/response and agent I/O."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ── Enums as Literals ────────────────────────────────────────

EventType = Literal["phishing_email", "auth_log", "malware_alert"]
IncidentStatus = Literal["analyzing", "awaiting_review", "resolved", "escalated"]
Severity = Literal["Low", "Medium", "High", "Critical"]
IOCType = Literal["ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256", "username"]
ActionType = Literal[
    "block_ip", "block_domain", "quarantine_email",
    "lock_account", "force_password_reset", "revoke_sessions",
]
ActionStatus = Literal["pending", "approved", "rejected", "executed_simulated", "rolled_back"]
RiskLevel = Literal["low", "medium", "high"]
IntelSource = Literal["virustotal", "abuseipdb", "mock"]


# ── API Request Schemas ──────────────────────────────────────

class EventCreate(BaseModel):
    """Submit a new event for analysis."""
    event_type: EventType
    raw_content: str = Field(..., max_length=51200, description="Raw email or log content (max 50KB)")
    source: str = Field(default="manual", max_length=255)


class ActionApproval(BaseModel):
    """Approve or reject an action."""
    analyst_comment: Optional[str] = Field(None, max_length=2000)
    approved_by: str = Field(default="analyst", max_length=255)


class SimulateRequest(BaseModel):
    """Request to generate and process a simulated event."""
    event_type: Optional[EventType] = None
    scenario: Optional[str] = None
    count: int = Field(default=1, ge=1, le=20)


# ── API Response Schemas ─────────────────────────────────────

class IOCResponse(BaseModel):
    id: str
    ioc_type: IOCType
    value: str
    context: Optional[str] = None

    model_config = {"from_attributes": True}


class ThreatIntelResultResponse(BaseModel):
    id: str
    ioc_id: str
    source: IntelSource
    reputation_score: float
    malicious: bool
    raw_response: Optional[dict[str, Any]] = None
    cached: bool
    queried_at: datetime

    model_config = {"from_attributes": True}


class ContainmentActionResponse(BaseModel):
    id: str
    incident_id: str
    action_type: ActionType
    target: str
    rationale: Optional[str] = None
    risk_level: RiskLevel
    reversible: bool
    command_text: Optional[str] = None
    rollback_command: Optional[str] = None
    status: ActionStatus
    analyst_comment: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    is_recommended: bool = False
    warning: Optional[str] = None

    model_config = {"from_attributes": True}


class AgentStepResponse(BaseModel):
    id: str
    agent_name: str
    input_summary: Optional[str] = None
    output_summary: Optional[str] = None
    reasoning: Optional[str] = None
    duration_ms: Optional[int] = None
    status: str
    error_message: Optional[str] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    id: str
    incident_id: Optional[str] = None
    actor: str
    action: str
    details: Optional[dict[str, Any]] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class EventResponse(BaseModel):
    id: str
    event_type: EventType
    raw_content: str
    source: str
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentSummaryResponse(BaseModel):
    """Lightweight incident for the queue/list view."""
    id: str
    event_id: str
    status: IncidentStatus
    severity: Optional[Severity] = None
    summary: Optional[str] = None
    incident_type: Optional[str] = None
    confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    ioc_count: int = 0
    action_count: int = 0
    pending_action_count: int = 0

    model_config = {"from_attributes": True}


class IncidentDetailResponse(BaseModel):
    """Full incident detail with all nested data."""
    id: str
    event_id: str
    status: IncidentStatus
    severity: Optional[Severity] = None
    summary: Optional[str] = None
    incident_type: Optional[str] = None
    confidence: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    event: EventResponse
    iocs: list[IOCResponse] = []
    threat_intel_results: list[ThreatIntelResultResponse] = []
    actions: list[ContainmentActionResponse] = []
    agent_steps: list[AgentStepResponse] = []
    audit_logs: list[AuditLogResponse] = []

    model_config = {"from_attributes": True}


class StatsResponse(BaseModel):
    """Dashboard statistics."""
    incidents_today: int = 0
    total_incidents: int = 0
    open_incidents: int = 0
    critical_incidents: int = 0
    high_incidents: int = 0
    medium_incidents: int = 0
    low_incidents: int = 0
    total_actions: int = 0
    approved_actions: int = 0
    rejected_actions: int = 0
    pending_actions: int = 0
    approval_rate: float = 0.0
    mean_time_to_respond_seconds: Optional[float] = None


# ── Agent I/O Schemas ────────────────────────────────────────

class IOCItem(BaseModel):
    """Single IOC extracted by the Log-Analyzer."""
    ioc_type: IOCType
    value: str
    context: Optional[str] = None


class LLMAnalysis(BaseModel):
    """Structured output from the LLM analysis step."""
    spoofed_headers: bool = False
    spf_dkim_failure: bool = False
    impossible_travel: bool = False
    brute_force_pattern: bool = False
    urgency_language: bool = False
    credential_harvesting: bool = False
    summary: str = ""
    incident_type: str = ""
    confidence: float = 0.5
    reasoning: str = ""


class LogAnalyzerInput(BaseModel):
    """Input to the Log-Analyzer agent."""
    event_id: str
    event_type: EventType
    raw_content: str = Field(..., max_length=51200)


class LogAnalyzerOutput(BaseModel):
    """Output from the Log-Analyzer agent."""
    iocs: list[IOCItem] = []
    summary: str = ""
    incident_type: str = ""
    llm_analysis: Optional[LLMAnalysis] = None
    confidence: float = 0.5


class IOCThreatResult(BaseModel):
    """Threat intel result for a single IOC."""
    ioc_type: IOCType
    ioc_value: str
    source: IntelSource
    reputation_score: float = Field(ge=0, le=100)
    malicious: bool = False
    details: Optional[dict[str, Any]] = None
    cached: bool = False


class ThreatIntelInput(BaseModel):
    """Input to the Threat-Intel agent."""
    incident_id: str
    iocs: list[IOCItem]


class ThreatIntelOutput(BaseModel):
    """Output from the Threat-Intel agent."""
    ioc_results: list[IOCThreatResult] = []
    overall_severity: Severity = "Low"
    confidence: float = 0.5
    reasoning: str = ""


class ContainmentActionItem(BaseModel):
    """A single proposed containment action."""
    action_type: ActionType
    target: str
    rationale: str = ""
    risk_level: RiskLevel = "medium"
    reversible: bool = True
    command_text: str = ""
    rollback_command: str = ""
    is_recommended: bool = False
    warning: Optional[str] = None


class ContainmentInput(BaseModel):
    """Input to the Containment agent."""
    incident_id: str
    incident_type: str
    severity: Severity
    summary: str
    iocs: list[IOCItem]
    threat_intel: ThreatIntelOutput


class ContainmentOutput(BaseModel):
    """Output from the Containment agent."""
    actions: list[ContainmentActionItem] = []
    warnings: list[str] = []
    recommended_action_indices: list[int] = []


# ── WebSocket Event Schemas ──────────────────────────────────

class WSEvent(BaseModel):
    """WebSocket event pushed to the frontend."""
    event_type: Literal[
        "incident_created",
        "analysis_complete",
        "enrichment_complete",
        "actions_ready",
        "action_updated",
        "incident_resolved",
    ]
    incident_id: str
    data: dict[str, Any] = {}
