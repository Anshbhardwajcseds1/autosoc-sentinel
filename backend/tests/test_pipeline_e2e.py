"""End-to-End integration tests for the AutoSOC Sentinel API and pipeline."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine, init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


class TestPipelineE2E:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mock_mode"] is True

    def test_simulate_attack_and_review_workflow(self, client):
        # 1. Trigger simulated attack
        resp = client.post(
            "/api/simulate",
            json={"event_type": "phishing_email", "scenario": "credential_phishing"},
        )
        assert resp.status_code == 200
        sim_data = resp.json()
        assert sim_data["status"] == "completed"
        incident_id = sim_data["incident_id"]
        assert incident_id is not None
        assert sim_data["actions_count"] > 0

        # 2. Get incident details
        inc_resp = client.get(f"/api/incidents/{incident_id}")
        assert inc_resp.status_code == 200
        inc_data = inc_resp.json()
        assert inc_data["id"] == incident_id
        assert inc_data["status"] == "awaiting_review"
        assert len(inc_data["iocs"]) > 0
        assert len(inc_data["threat_intel_results"]) > 0
        assert len(inc_data["actions"]) > 0
        assert len(inc_data["agent_steps"]) >= 3

        # Verify agent steps order and names
        agent_names = [s["agent_name"] for s in inc_data["agent_steps"]]
        assert "log_analyzer" in agent_names
        assert "threat_intel" in agent_names
        assert "containment" in agent_names

        # 3. Find a pending action to approve
        actions = inc_data["actions"]
        pending_action = next(a for a in actions if a["status"] == "pending")
        action_id = pending_action["id"]

        # Approve the action
        appr_resp = client.post(
            f"/api/incidents/{incident_id}/actions/{action_id}/approve",
            json={"analyst_comment": "Approved following SOC playbook", "approved_by": "analyst-alice"},
        )
        assert appr_resp.status_code == 200
        appr_data = appr_resp.json()
        assert appr_data["action_status"] == "executed_simulated"
        assert "[SIMULATED CONTAINMENT DISPATCH]" in appr_data["execution"]["simulation_log"]

        # 4. Rollback the executed action
        if pending_action["reversible"]:
            rb_resp = client.post(
                f"/api/incidents/{incident_id}/actions/{action_id}/rollback",
                json={"approved_by": "analyst-alice"},
            )
            assert rb_resp.status_code == 200
            rb_data = rb_resp.json()
            assert rb_data["action_status"] == "rolled_back"
            assert "[SIMULATED CONTAINMENT ROLLBACK]" in rb_data["rollback"]["simulation_log"]

        # 5. Check audit log for the incident
        audit_resp = client.get(f"/api/incidents/{incident_id}/audit-log")
        assert audit_resp.status_code == 200
        audit_entries = audit_resp.json()
        assert len(audit_entries) >= 2
        actors = [entry["actor"] for entry in audit_entries]
        assert "simulated_executor" in actors

        # 6. Check stats endpoint
        stats_resp = client.get("/api/stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_incidents"] >= 1
        assert stats["total_actions"] >= 1

    def test_approve_all_recommended(self, client):
        # Generate another attack
        sim_resp = client.post(
            "/api/simulate",
            json={"event_type": "auth_log", "scenario": "brute_force"},
        )
        inc_id = sim_resp.json()["incident_id"]

        # One-click approve recommended
        batch_resp = client.post(
            f"/api/incidents/{inc_id}/actions/approve-recommended",
            json={"approved_by": "analyst-bob"},
        )
        assert batch_resp.status_code == 200
        batch_data = batch_resp.json()
        assert batch_data["status"] == "success"
        assert batch_data["approved_count"] >= 1

        # Verify incident actions updated
        inc_resp = client.get(f"/api/incidents/{inc_id}")
        inc = inc_resp.json()
        executed_count = sum(1 for a in inc["actions"] if a["status"] == "executed_simulated")
        assert executed_count == batch_data["approved_count"]
