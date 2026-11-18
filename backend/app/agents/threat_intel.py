"""Threat-Intel Agent: Enriches IOCs and determines overall incident severity."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent
from app.models.schemas import (
    IOCThreatResult,
    Severity,
    ThreatIntelInput,
    ThreatIntelOutput,
)
from app.services.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)


def compute_severity(results: list[IOCThreatResult]) -> tuple[Severity, float, str]:
    """
    Compute aggregate incident severity from individual IOC threat results.
    Returns (severity, confidence, reasoning).
    """
    if not results:
        return "Low", 0.60, "No external IOCs required threat intelligence enrichment."

    # Max IOC reputation score is the strongest signal
    scores = [r.reputation_score for r in results]
    max_score = max(scores)
    malicious_count = sum(1 for r in results if r.malicious)

    # Weights: high score has significant gravity
    avg_score = sum(scores) / len(scores)
    blended_score = (max_score * 0.7) + (avg_score * 0.3)

    if max_score >= 85.0 or malicious_count >= 2:
        severity: Severity = "Critical" if max_score >= 92.0 else "High"
    elif max_score >= 50.0 or blended_score >= 40.0:
        severity = "Medium"
    else:
        severity = "Low"

    confidence = min(0.98, 0.70 + (len(results) * 0.05))

    reasoning = (
        f"Enriched {len(results)} indicators. Found {malicious_count} malicious indicator(s). "
        f"Peak threat reputation score was {max_score:.1f}/100. "
        f"Assigned severity: {severity}."
    )
    return severity, confidence, reasoning


class ThreatIntelAgent(BaseAgent[ThreatIntelInput, ThreatIntelOutput]):
    """Enriches extracted IOCs with multi-source threat intelligence."""

    name = "threat_intel"

    def __init__(self, service: Optional[ThreatIntelService] = None, db_session: Optional[Session] = None):
        self.service = service or ThreatIntelService(db_session=db_session)

    async def run(self, input_data: ThreatIntelInput) -> ThreatIntelOutput:
        logger.info("ThreatIntelAgent enriching %d IOCs for incident: %s", len(input_data.iocs), input_data.incident_id)

        all_results: list[IOCThreatResult] = []

        for ioc in input_data.iocs:
            # Skip usernames from threat intel queries
            if ioc.ioc_type == "username":
                continue
            enriched = await self.service.enrich_ioc(ioc)
            all_results.extend(enriched)

        severity, confidence, reasoning = compute_severity(all_results)

        return ThreatIntelOutput(
            ioc_results=all_results,
            overall_severity=severity,
            confidence=confidence,
            reasoning=reasoning,
        )
