"""Tests for Threat-Intel Agent and Service."""

from __future__ import annotations

import pytest

from app.agents.threat_intel import ThreatIntelAgent, compute_severity
from app.models.schemas import IOCItem, IOCThreatResult, ThreatIntelInput
from app.services.threat_intel_service import ThreatIntelService, is_private_ip


class TestThreatIntelService:
    def test_private_ip_detection(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("192.168.1.50") is True
        assert is_private_ip("172.16.5.10") is True
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("45.33.32.156") is False

    @pytest.mark.asyncio
    async def test_mock_private_ip(self, db_session):
        service = ThreatIntelService(db_session=db_session)
        results = await service.enrich_ioc(IOCItem(ioc_type="ip", value="10.0.0.5"))
        assert len(results) == 1
        assert results[0].reputation_score == 0.0
        assert results[0].malicious is False

    @pytest.mark.asyncio
    async def test_mock_malicious_ip(self, db_session):
        service = ThreatIntelService(db_session=db_session)
        # 185 is one of the simulator malicious octets
        results = await service.enrich_ioc(IOCItem(ioc_type="ip", value="185.220.101.5"))
        assert len(results) == 1
        assert results[0].reputation_score >= 80.0
        assert results[0].malicious is True

    @pytest.mark.asyncio
    async def test_mock_phishing_domain(self, db_session):
        service = ThreatIntelService(db_session=db_session)
        results = await service.enrich_ioc(IOCItem(ioc_type="domain", value="secure-login-portal.xyz"))
        assert len(results) == 1
        assert results[0].reputation_score > 90.0
        assert results[0].malicious is True

    @pytest.mark.asyncio
    async def test_mock_benign_domain(self, db_session):
        service = ThreatIntelService(db_session=db_session)
        results = await service.enrich_ioc(IOCItem(ioc_type="domain", value="github.com"))
        assert len(results) == 1
        assert results[0].reputation_score == 0.0
        assert results[0].malicious is False


class TestThreatIntelAgent:
    def test_compute_severity_critical(self):
        results = [
            IOCThreatResult(
                ioc_type="ip",
                ioc_value="45.1.1.1",
                source="mock",
                reputation_score=95.0,
                malicious=True,
            ),
            IOCThreatResult(
                ioc_type="domain",
                ioc_value="bad.xyz",
                source="mock",
                reputation_score=94.0,
                malicious=True,
            ),
        ]
        sev, conf, reason = compute_severity(results)
        assert sev == "Critical"
        assert conf >= 0.7

    def test_compute_severity_low(self):
        results = [
            IOCThreatResult(
                ioc_type="ip",
                ioc_value="8.8.8.8",
                source="mock",
                reputation_score=5.0,
                malicious=False,
            )
        ]
        sev, conf, reason = compute_severity(results)
        assert sev == "Low"

    @pytest.mark.asyncio
    async def test_agent_run(self, db_session):
        agent = ThreatIntelAgent(db_session=db_session)
        inp = ThreatIntelInput(
            incident_id="inc-1",
            iocs=[
                IOCItem(ioc_type="ip", value="185.1.2.3"),
                IOCItem(ioc_type="domain", value="evil-login.xyz"),
            ],
        )
        out, duration = await agent.execute(inp)
        assert out.overall_severity in ("High", "Critical")
        assert len(out.ioc_results) == 2
        assert duration >= 0
