"""Phase 1 tests: models, database, and simulator."""

from __future__ import annotations

import json
import pytest

from app.config import get_settings
from app.database import init_db, Base, engine, SessionLocal
from app.models.db_models import Event, Incident, IOC, ContainmentAction, AuditLog, AgentStep
from app.models.schemas import (
    EventCreate, LogAnalyzerInput, LogAnalyzerOutput, IOCItem,
    ThreatIntelOutput, ContainmentOutput, ContainmentActionItem,
    SimulateRequest, ActionApproval,
)

# Import simulator - add parent dir to path
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from simulator.generator import generate_event, generate_batch, GENERATORS, ALL_SCENARIOS


class TestConfig:
    def test_settings_load(self):
        settings = get_settings()
        assert settings.mock_mode is True
        assert settings.database_url == "sqlite:///./test_autosoc.db"

    def test_private_networks(self):
        settings = get_settings()
        nets = settings.private_networks
        assert len(nets) >= 4


class TestDatabase:
    def test_create_tables(self, db_session):
        """Verify all tables are created."""
        tables = Base.metadata.tables.keys()
        expected = {
            "events", "incidents", "iocs", "threat_intel_results",
            "containment_actions", "agent_steps", "audit_logs", "threat_intel_cache",
        }
        assert expected.issubset(set(tables))

    def test_create_event(self, db_session):
        event = Event(event_type="phishing_email", raw_content="test content", source="test")
        db_session.add(event)
        db_session.commit()

        fetched = db_session.query(Event).first()
        assert fetched is not None
        assert fetched.event_type == "phishing_email"
        assert fetched.raw_content == "test content"
        assert fetched.id is not None

    def test_create_incident_with_event(self, db_session):
        event = Event(event_type="auth_log", raw_content="auth log content", source="test")
        db_session.add(event)
        db_session.flush()

        incident = Incident(event_id=event.id, status="analyzing")
        db_session.add(incident)
        db_session.commit()

        fetched = db_session.query(Incident).first()
        assert fetched.event_id == event.id
        assert fetched.status == "analyzing"

    def test_create_ioc(self, db_session):
        event = Event(event_type="phishing_email", raw_content="test", source="test")
        db_session.add(event)
        db_session.flush()

        incident = Incident(event_id=event.id)
        db_session.add(incident)
        db_session.flush()

        ioc = IOC(incident_id=incident.id, ioc_type="ip", value="45.33.32.156", context="From header")
        db_session.add(ioc)
        db_session.commit()

        fetched = db_session.query(IOC).first()
        assert fetched.ioc_type == "ip"
        assert fetched.value == "45.33.32.156"

    def test_create_containment_action(self, db_session):
        event = Event(event_type="phishing_email", raw_content="test", source="test")
        db_session.add(event)
        db_session.flush()

        incident = Incident(event_id=event.id)
        db_session.add(incident)
        db_session.flush()

        action = ContainmentAction(
            incident_id=incident.id,
            action_type="block_ip",
            target="45.33.32.156",
            rationale="Malicious IP",
            risk_level="low",
            command_text="iptables -A INPUT -s 45.33.32.156 -j DROP",
            rollback_command="iptables -D INPUT -s 45.33.32.156 -j DROP",
            status="pending",
        )
        db_session.add(action)
        db_session.commit()

        fetched = db_session.query(ContainmentAction).first()
        assert fetched.action_type == "block_ip"
        assert fetched.status == "pending"

    def test_audit_log(self, db_session):
        log = AuditLog(actor="system", action="test_action", details={"key": "value"})
        db_session.add(log)
        db_session.commit()

        fetched = db_session.query(AuditLog).first()
        assert fetched.actor == "system"
        assert fetched.details == {"key": "value"}


class TestSchemas:
    def test_event_create_valid(self):
        event = EventCreate(
            event_type="phishing_email",
            raw_content="test content",
            source="manual",
        )
        assert event.event_type == "phishing_email"

    def test_event_create_invalid_type(self):
        with pytest.raises(Exception):
            EventCreate(event_type="invalid_type", raw_content="test")

    def test_event_create_max_length(self):
        with pytest.raises(Exception):
            EventCreate(event_type="phishing_email", raw_content="x" * 60000)

    def test_ioc_item(self):
        ioc = IOCItem(ioc_type="ip", value="1.2.3.4", context="test")
        assert ioc.ioc_type == "ip"

    def test_log_analyzer_output(self):
        output = LogAnalyzerOutput(
            iocs=[IOCItem(ioc_type="ip", value="1.2.3.4")],
            summary="Test summary",
            incident_type="brute_force",
            confidence=0.9,
        )
        assert len(output.iocs) == 1
        assert output.confidence == 0.9

    def test_containment_action_item(self):
        action = ContainmentActionItem(
            action_type="block_ip",
            target="1.2.3.4",
            rationale="Malicious",
            risk_level="low",
            command_text="iptables -A INPUT -s 1.2.3.4 -j DROP",
            rollback_command="iptables -D INPUT -s 1.2.3.4 -j DROP",
        )
        assert action.action_type == "block_ip"

    def test_simulate_request(self):
        req = SimulateRequest(event_type="phishing_email", count=5)
        assert req.count == 5

    def test_simulate_request_max_count(self):
        with pytest.raises(Exception):
            SimulateRequest(count=100)


class TestSimulator:
    def test_generate_single_event(self):
        event = generate_event()
        assert "event_type" in event
        assert "raw_content" in event
        assert "source" in event
        assert "is_malicious" in event
        assert event["event_type"] in ["phishing_email", "auth_log", "malware_alert"]

    def test_generate_phishing_email(self):
        event = generate_event(event_type="phishing_email")
        assert event["event_type"] == "phishing_email"
        assert len(event["raw_content"]) > 100

    def test_generate_auth_log(self):
        event = generate_event(event_type="auth_log")
        assert event["event_type"] == "auth_log"

    def test_generate_malware_alert(self):
        event = generate_event(event_type="malware_alert")
        assert event["event_type"] == "malware_alert"

    def test_generate_specific_scenario(self):
        event = generate_event(event_type="phishing_email", scenario="ceo_fraud")
        assert event["scenario"] == "ceo_fraud"
        assert event["is_malicious"] is True

    def test_generate_benign_email(self):
        event = generate_event(event_type="phishing_email", scenario="benign_email")
        assert event["is_malicious"] is False

    def test_generate_brute_force(self):
        event = generate_event(event_type="auth_log", scenario="brute_force")
        assert event["scenario"] == "brute_force"
        # Should contain many log lines
        lines = event["raw_content"].split("\n")
        assert len(lines) > 50

    def test_generate_impossible_travel(self):
        event = generate_event(event_type="auth_log", scenario="impossible_travel")
        assert "geo=US" in event["raw_content"]
        assert "geo=RU" in event["raw_content"]

    def test_generate_batch(self):
        events = generate_batch(count=5)
        assert len(events) == 5
        for e in events:
            assert "event_type" in e
            assert "raw_content" in e

    def test_generate_batch_typed(self):
        events = generate_batch(count=3, event_type="auth_log")
        assert len(events) == 3
        for e in events:
            assert e["event_type"] == "auth_log"

    def test_all_scenarios_registered(self):
        assert len(ALL_SCENARIOS) == 12  # 5 phishing + 5 auth + 2 malware

    def test_all_scenarios_generate(self):
        """Every registered scenario must produce a valid event."""
        for event_type, scenario in ALL_SCENARIOS:
            event = generate_event(event_type=event_type, scenario=scenario)
            assert event["event_type"] == event_type
            assert len(event["raw_content"]) > 0

    def test_invalid_event_type(self):
        with pytest.raises(ValueError):
            generate_event(event_type="invalid")

    def test_invalid_scenario(self):
        with pytest.raises(ValueError):
            generate_event(event_type="phishing_email", scenario="nonexistent")

    def test_phishing_has_email_headers(self):
        """Phishing emails should contain realistic headers."""
        for scenario in ["ceo_fraud", "credential_phishing", "malware_attachment", "internal_spoof"]:
            event = generate_event(event_type="phishing_email", scenario=scenario)
            content = event["raw_content"]
            assert "From:" in content
            assert "To:" in content
            assert "Subject:" in content
            assert "X-SPF-Result:" in content
