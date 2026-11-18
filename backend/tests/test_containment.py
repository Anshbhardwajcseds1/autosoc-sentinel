"""Tests for Containment Agent and allowlist validation."""

from __future__ import annotations

import pytest

from app.agents.containment import (
    ContainmentAgent,
    is_account_in_allowlist,
    is_ip_in_allowlist,
)
from app.models.schemas import (
    ContainmentInput,
    IOCItem,
    IOCThreatResult,
    ThreatIntelOutput,
)


class TestAllowlistValidation:
    def test_private_ips_blocked_from_firewall(self):
        analyst_ips = ["203.0.113.5"]
        assert is_ip_in_allowlist("10.0.0.1", analyst_ips)[0] is True
        assert is_ip_in_allowlist("172.16.0.5", analyst_ips)[0] is True
        assert is_ip_in_allowlist("192.168.1.100", analyst_ips)[0] is True
        assert is_ip_in_allowlist("127.0.0.1", analyst_ips)[0] is True

    def test_analyst_ip_blocked_from_firewall(self):
        analyst_ips = ["54.210.10.42", "64.104.20.10"]
        assert is_ip_in_allowlist("54.210.10.42", analyst_ips)[0] is True
        assert is_ip_in_allowlist("64.104.20.10", analyst_ips)[0] is True
        assert is_ip_in_allowlist("54.210.10.99", analyst_ips)[0] is False

    def test_external_ip_permitted(self):
        analyst_ips = ["198.51.100.42"]
        assert is_ip_in_allowlist("45.33.32.156", analyst_ips)[0] is False
        assert is_ip_in_allowlist("185.220.101.5", analyst_ips)[0] is False

    def test_admin_account_protected(self):
        admin_accounts = ["admin", "soc-admin", "service-account"]
        assert is_account_in_allowlist("admin", admin_accounts)[0] is True
        assert is_account_in_allowlist("SOC-ADMIN", admin_accounts)[0] is True
        assert is_account_in_allowlist("service-account", admin_accounts)[0] is True
        assert is_account_in_allowlist("john.smith", admin_accounts)[0] is False


class TestContainmentAgentExecution:
    @pytest.mark.asyncio
    async def test_containment_generation_for_malicious_ip(self):
        agent = ContainmentAgent()
        inp = ContainmentInput(
            incident_id="inc-test-1",
            incident_type="brute_force",
            severity="High",
            summary="Brute force attack from external IP",
            iocs=[
                IOCItem(ioc_type="ip", value="185.220.101.5"),
                IOCItem(ioc_type="username", value="carlos.danger"),
            ],
            threat_intel=ThreatIntelOutput(
                overall_severity="High",
                ioc_results=[
                    IOCThreatResult(
                        ioc_type="ip",
                        ioc_value="185.220.101.5",
                        source="mock",
                        reputation_score=95.0,
                        malicious=True,
                    )
                ],
            ),
        )

        out, duration = await agent.execute(inp)
        assert len(out.actions) >= 2
        # Verify block_ip action exists and has rollback
        ip_actions = [a for a in out.actions if a.action_type == "block_ip"]
        assert len(ip_actions) == 1
        assert "iptables -A" in ip_actions[0].command_text
        assert "iptables -D" in ip_actions[0].rollback_command
        assert ip_actions[0].is_recommended is True

        # Verify user action exists
        user_actions = [a for a in out.actions if a.action_type in ("lock_account", "revoke_sessions")]
        assert len(user_actions) >= 1

    @pytest.mark.asyncio
    async def test_allowlist_enforcement_in_agent(self):
        agent = ContainmentAgent()
        inp = ContainmentInput(
            incident_id="inc-test-2",
            incident_type="brute_force",
            severity="High",
            summary="Suspicious test from private IP",
            iocs=[
                IOCItem(ioc_type="ip", value="10.0.0.99"),  # RFC 1918 private!
                IOCItem(ioc_type="username", value="admin"),  # Protected admin!
            ],
            threat_intel=ThreatIntelOutput(
                overall_severity="High",
                ioc_results=[],
            ),
        )

        out, _ = await agent.execute(inp)
        assert len(out.warnings) >= 2
        # IP action must have warning and not be recommended
        ip_action = next(a for a in out.actions if a.action_type == "block_ip")
        assert ip_action.is_recommended is False
        assert ip_action.risk_level == "high"
        assert "ALLOWLIST" in (ip_action.warning or "")

        # Admin account lock must have warning and not be recommended
        lock_action = next(a for a in out.actions if a.action_type == "lock_account")
        assert lock_action.is_recommended is False
        assert lock_action.risk_level == "high"
        assert "ALLOWLIST" in (lock_action.warning or "")
