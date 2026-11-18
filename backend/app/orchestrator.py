"""Orchestrator pipeline: Runs AI agents sequentially and updates incident state."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.agents.containment import ContainmentAgent
from app.agents.log_analyzer import LogAnalyzerAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.api.websocket import ws_manager
from app.models.db_models import (
    AgentStep,
    ContainmentAction,
    Event,
    Incident,
    IOC,
    ThreatIntelResult,
)
from app.models.schemas import (
    ContainmentInput,
    IOCItem,
    LogAnalyzerInput,
    ThreatIntelInput,
)
from app.services.audit import AuditService
from app.services.llm_service import get_llm_provider
from app.services.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)


class Orchestrator:
    """Orchestrates multi-agent analysis, threat intel enrichment, and containment drafting."""

    def __init__(self, db: Session):
        self.db = db
        self.audit = AuditService(db_session=db)
        self.log_analyzer = LogAnalyzerAgent(llm=get_llm_provider())
        self.threat_intel = ThreatIntelAgent(
            service=ThreatIntelService(db_session=db), db_session=db
        )
        self.containment = ContainmentAgent()

    async def run_pipeline(self, event_id: str) -> Incident:
        """Run the complete agent pipeline for an ingested event."""
        event: Optional[Event] = self.db.query(Event).filter(Event.id == event_id).first()
        if not event:
            raise ValueError(f"Event {event_id} not found")

        # Find or create Incident
        incident: Optional[Incident] = (
            self.db.query(Incident).filter(Incident.event_id == event_id).first()
        )
        if not incident:
            incident = Incident(
                event_id=event.id,
                status="analyzing",
                summary="Pipeline initialized...",
            )
            self.db.add(incident)
            self.db.commit()
            self.db.refresh(incident)

        self.audit.log_action(
            actor="orchestrator",
            action="pipeline_started",
            incident_id=incident.id,
            details={"event_type": event.event_type, "source": event.source},
        )

        await ws_manager.broadcast("incident_created", incident.id, {"status": "analyzing"})

        # ── Step 1: Log-Analyzer Agent ────────────────────────
        step1_err = None
        analyzer_output = None
        duration_ms_1 = 0
        try:
            inp_analyzer = LogAnalyzerInput(
                event_id=event.id,
                event_type=event.event_type,  # type: ignore
                raw_content=event.raw_content,
            )
            analyzer_output, duration_ms_1 = await self.log_analyzer.execute(inp_analyzer)

            # Save extracted IOCs
            created_iocs = []
            for item in analyzer_output.iocs:
                ioc_record = IOC(
                    incident_id=incident.id,
                    ioc_type=item.ioc_type,
                    value=item.value,
                    context=item.context,
                )
                self.db.add(ioc_record)
                created_iocs.append(ioc_record)

            incident.summary = analyzer_output.summary
            incident.incident_type = analyzer_output.incident_type
            incident.confidence = analyzer_output.confidence

            # Record step
            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="log_analyzer",
                input_summary=f"Raw {event.event_type} content ({len(event.raw_content)} chars)",
                output_summary=f"Extracted {len(analyzer_output.iocs)} IOCs. Type: {analyzer_output.incident_type}",
                reasoning=analyzer_output.llm_analysis.reasoning if analyzer_output.llm_analysis else "",
                duration_ms=duration_ms_1,
                status="success",
            )
            self.db.add(step_record)
            self.db.commit()

            await ws_manager.broadcast(
                "analysis_complete",
                incident.id,
                {
                    "ioc_count": len(analyzer_output.iocs),
                    "incident_type": incident.incident_type,
                    "summary": incident.summary,
                },
            )

        except Exception as e:
            step1_err = str(e)
            logger.error("Log-Analyzer step failed: %s\n%s", e, traceback.format_exc())
            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="log_analyzer",
                duration_ms=duration_ms_1,
                status="error",
                error_message=step1_err,
            )
            self.db.add(step_record)
            self.db.commit()

        # ── Step 2: Threat-Intel Agent ────────────────────────
        step2_err = None
        intel_output = None
        duration_ms_2 = 0
        try:
            ioc_items = analyzer_output.iocs if analyzer_output else []
            inp_intel = ThreatIntelInput(
                incident_id=incident.id,
                iocs=ioc_items,
            )
            intel_output, duration_ms_2 = await self.threat_intel.execute(inp_intel)

            # Persist threat intel results mapped to DB IOCs
            db_iocs = {i.value: i.id for i in self.db.query(IOC).filter(IOC.incident_id == incident.id).all()}
            for r in intel_output.ioc_results:
                ioc_id = db_iocs.get(r.ioc_value)
                if ioc_id:
                    tir = ThreatIntelResult(
                        ioc_id=ioc_id,
                        source=r.source,
                        reputation_score=r.reputation_score,
                        malicious=r.malicious,
                        raw_response=r.details,
                        cached=r.cached,
                    )
                    self.db.add(tir)

            incident.severity = intel_output.overall_severity

            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="threat_intel",
                input_summary=f"Queried intelligence for {len(ioc_items)} indicators",
                output_summary=f"Severity: {intel_output.overall_severity} ({intel_output.reasoning})",
                reasoning=intel_output.reasoning,
                duration_ms=duration_ms_2,
                status="success",
            )
            self.db.add(step_record)
            self.db.commit()

            await ws_manager.broadcast(
                "enrichment_complete",
                incident.id,
                {
                    "severity": incident.severity,
                    "reasoning": intel_output.reasoning,
                },
            )

        except Exception as e:
            step2_err = str(e)
            logger.error("Threat-Intel step failed: %s\n%s", e, traceback.format_exc())
            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="threat_intel",
                duration_ms=duration_ms_2,
                status="error",
                error_message=step2_err,
            )
            self.db.add(step_record)
            self.db.commit()

        # ── Step 3: Containment Agent ─────────────────────────
        step3_err = None
        duration_ms_3 = 0
        try:
            inp_containment = ContainmentInput(
                incident_id=incident.id,
                incident_type=incident.incident_type or "suspicious_event",
                severity=incident.severity or "Medium",  # type: ignore
                summary=incident.summary or "",
                iocs=analyzer_output.iocs if analyzer_output else [],
                threat_intel=intel_output,  # type: ignore
            )
            containment_output, duration_ms_3 = await self.containment.execute(inp_containment)

            for idx, action_item in enumerate(containment_output.actions):
                ca = ContainmentAction(
                    incident_id=incident.id,
                    action_type=action_item.action_type,
                    target=action_item.target,
                    rationale=action_item.rationale,
                    risk_level=action_item.risk_level,
                    reversible=action_item.reversible,
                    command_text=action_item.command_text,
                    rollback_command=action_item.rollback_command,
                    status="pending",
                    is_recommended=idx in containment_output.recommended_action_indices,
                    warning=action_item.warning,
                )
                self.db.add(ca)

            incident.status = "awaiting_review"

            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="containment",
                input_summary=f"Drafted actions for {incident.severity} {incident.incident_type}",
                output_summary=f"Proposed {len(containment_output.actions)} containment actions ({len(containment_output.recommended_action_indices)} recommended)",
                reasoning=f"Enforced allowlist policy with {len(containment_output.warnings)} safety warnings.",
                duration_ms=duration_ms_3,
                status="success",
            )
            self.db.add(step_record)
            self.db.commit()

            self.audit.log_action(
                actor="orchestrator",
                action="actions_drafted",
                incident_id=incident.id,
                details={
                    "total_actions": len(containment_output.actions),
                    "recommended_count": len(containment_output.recommended_action_indices),
                },
            )

            await ws_manager.broadcast(
                "actions_ready",
                incident.id,
                {
                    "status": incident.status,
                    "action_count": len(containment_output.actions),
                },
            )

        except Exception as e:
            step3_err = str(e)
            logger.error("Containment step failed: %s\n%s", e, traceback.format_exc())
            step_record = AgentStep(
                incident_id=incident.id,
                agent_name="containment",
                duration_ms=duration_ms_3,
                status="error",
                error_message=step3_err,
            )
            self.db.add(step_record)
            self.db.commit()

        self.db.refresh(incident)
        return incident
