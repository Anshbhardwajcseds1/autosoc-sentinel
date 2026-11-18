"""Containment Agent: Rule generation, rollback commands, and strict allowlist enforcement."""

from __future__ import annotations

import ipaddress
import logging
from typing import List, Optional

from app.agents.base import BaseAgent
from app.config import get_settings
from app.models.schemas import (
    ActionType,
    ContainmentActionItem,
    ContainmentInput,
    ContainmentOutput,
    IOCItem,
    RiskLevel,
)

logger = logging.getLogger(__name__)


def is_ip_in_allowlist(ip_str: str, analyst_ips: list[str]) -> tuple[bool, str]:
    """Check if an IP is in private ranges, loopback, or configured analyst IPs."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return True, f"RFC 1918 Private Network range ({ip_str})"
        if ip.is_loopback:
            return True, f"Loopback address ({ip_str})"

        for a_ip in analyst_ips:
            try:
                if ip == ipaddress.ip_address(a_ip):
                    return True, f"Designated SOC Analyst IP ({ip_str})"
            except ValueError:
                pass

        return False, ""
    except ValueError:
        return False, ""


def is_account_in_allowlist(username: str, admin_accounts: list[str]) -> tuple[bool, str]:
    """Check if account is a critical administrative or service account."""
    u_lower = username.lower().strip()
    for admin in admin_accounts:
        if u_lower == admin.lower().strip():
            return True, f"Critical protected administrative account ({username})"
    return False, ""


def generate_ip_commands(ip: str) -> tuple[str, str]:
    """Generate multi-platform firewall and security group rules + rollbacks."""
    apply_cmd = (
        f"# Linux iptables\n"
        f"iptables -A INPUT -s {ip} -j DROP\n"
        f"# UFW\n"
        f"ufw deny from {ip} to any\n"
        f"# AWS Security Group (Simulated)\n"
        f"aws ec2 revoke-security-group-ingress --group-id sg-soc-border --protocol all --cidr {ip}/32"
    )
    rollback_cmd = (
        f"# Linux iptables rollback\n"
        f"iptables -D INPUT -s {ip} -j DROP\n"
        f"# UFW rollback\n"
        f"ufw delete deny from {ip} to any\n"
        f"# AWS Security Group rollback\n"
        f"aws ec2 authorize-security-group-ingress --group-id sg-soc-border --protocol all --cidr {ip}/32"
    )
    return apply_cmd, rollback_cmd


def generate_domain_commands(domain: str) -> tuple[str, str]:
    """Generate DNS sinkhole and proxy block rules + rollbacks."""
    apply_cmd = (
        f"# DNS Sinkhole / BIND9 RPZ\n"
        f"{domain} CNAME sinkhole.internal.soc.\n"
        f"# CoreDNS / Pi-hole blocklist\n"
        f"0.0.0.0 {domain}"
    )
    rollback_cmd = (
        f"# DNS Sinkhole remove\n"
        f"# Remove {domain} from RPZ zone\n"
        f"rndc reload"
    )
    return apply_cmd, rollback_cmd


def generate_email_commands(target: str) -> tuple[str, str]:
    """Generate email quarantine and rollback commands."""
    apply_cmd = (
        f"# Microsoft Exchange / Google Workspace quarantine\n"
        f"Set-MailboxJunkEmailConfiguration -Identity '{target}' -Enabled $true\n"
        f"Search-Mailbox -Identity '{target}' -SearchDumpster -DeleteContent -Force"
    )
    rollback_cmd = (
        f"# Email quarantine release\n"
        f"# Release quarantined items for recipient '{target}' to inbox"
    )
    return apply_cmd, rollback_cmd


def generate_account_lock_commands(username: str) -> tuple[str, str]:
    """Generate IdP account lock and rollback commands."""
    apply_cmd = (
        f"# Active Directory / Azure AD\n"
        f"Disable-ADAccount -Identity '{username}'\n"
        f"# Okta API\n"
        f"POST /api/v1/users/{username}/lifecycle/suspend"
    )
    rollback_cmd = (
        f"# Account unlock\n"
        f"Enable-ADAccount -Identity '{username}'\n"
        f"# Okta API\n"
        f"POST /api/v1/users/{username}/lifecycle/unsuspend"
    )
    return apply_cmd, rollback_cmd


def generate_session_revoke_commands(username_or_ip: str) -> tuple[str, str]:
    """Generate OAuth session token revocation commands."""
    apply_cmd = (
        f"# Revoke active refresh tokens and OAuth sessions\n"
        f"Revoke-AzureADUserAllRefreshToken -ObjectId '{username_or_ip}'\n"
        f"# Redis session cache flush\n"
        f"redis-cli DEL 'session:user:{username_or_ip}:*'"
    )
    rollback_cmd = (
        f"# Sessions cannot be automatically restored; user must re-authenticate with MFA"
    )
    return apply_cmd, rollback_cmd


class ContainmentAgent(BaseAgent[ContainmentInput, ContainmentOutput]):
    """Drafts proposed containment actions with strict allowlist enforcement."""

    name = "containment"

    def __init__(self):
        self.settings = get_settings()

    async def run(self, input_data: ContainmentInput) -> ContainmentOutput:
        logger.info(
            "ContainmentAgent proposing actions for incident %s (severity=%s, type=%s)",
            input_data.incident_id,
            input_data.severity,
            input_data.incident_type,
        )

        actions: list[ContainmentActionItem] = []
        warnings: list[str] = []
        recommended_indices: list[int] = []

        # Find malicious indicators from threat intel
        malicious_iocs = {
            r.ioc_value: r for r in input_data.threat_intel.ioc_results if r.malicious
        }

        # 1. IP Containment
        for ioc in input_data.iocs:
            if ioc.ioc_type == "ip":
                is_allowed, allow_reason = is_ip_in_allowlist(
                    ioc.value, self.settings.analyst_ips
                )

                if is_allowed:
                    msg = f"SAFETY PREVENTED: Cannot block allowlisted IP '{ioc.value}' ({allow_reason})."
                    warnings.append(msg)
                    logger.warning(msg)
                    # Create an explicitly flagged high-risk rejected proposal
                    actions.append(
                        ContainmentActionItem(
                            action_type="block_ip",
                            target=ioc.value,
                            rationale=f"Proposed IP block blocked by SOC allowlist policy: {allow_reason}.",
                            risk_level="high",
                            reversible=True,
                            command_text=f"# BLOCKED BY ALLOWLIST: {allow_reason}",
                            rollback_command="# No-op",
                            is_recommended=False,
                            warning=f"ALLOWLIST POLICY VIOLATION: {allow_reason}",
                        )
                    )
                else:
                    is_mal = ioc.value in malicious_iocs or input_data.severity in ("High", "Critical")
                    apply_cmd, rollback_cmd = generate_ip_commands(ioc.value)
                    action = ContainmentActionItem(
                        action_type="block_ip",
                        target=ioc.value,
                        rationale=f"Block malicious ingress/egress IP with threat reputation score.",
                        risk_level="low" if is_mal else "medium",
                        reversible=True,
                        command_text=apply_cmd,
                        rollback_command=rollback_cmd,
                        is_recommended=is_mal,
                    )
                    actions.append(action)
                    if action.is_recommended:
                        recommended_indices.append(len(actions) - 1)

        # 2. Domain Containment
        for ioc in input_data.iocs:
            if ioc.ioc_type == "domain":
                is_mal = ioc.value in malicious_iocs or input_data.incident_type in ("credential_phishing", "ceo_fraud")
                apply_cmd, rollback_cmd = generate_domain_commands(ioc.value)
                action = ContainmentActionItem(
                    action_type="block_domain",
                    target=ioc.value,
                    rationale=f"DNS sinkhole domain to block credential harvesting and C2 callouts.",
                    risk_level="low",
                    reversible=True,
                    command_text=apply_cmd,
                    rollback_command=rollback_cmd,
                    is_recommended=is_mal,
                )
                actions.append(action)
                if action.is_recommended:
                    recommended_indices.append(len(actions) - 1)

        # 3. User Account Actions
        for ioc in input_data.iocs:
            if ioc.ioc_type == "username":
                is_admin, admin_reason = is_account_in_allowlist(
                    ioc.value, self.settings.admin_accounts
                )

                if is_admin:
                    msg = f"SAFETY PREVENTED: Cannot lock allowlisted admin account '{ioc.value}' ({admin_reason})."
                    warnings.append(msg)
                    actions.append(
                        ContainmentActionItem(
                            action_type="lock_account",
                            target=ioc.value,
                            rationale=f"Lockout prevented: {admin_reason}. Manual incident escalation required.",
                            risk_level="high",
                            reversible=True,
                            command_text=f"# BLOCKED BY ALLOWLIST: {admin_reason}",
                            rollback_command="# No-op",
                            is_recommended=False,
                            warning=f"ALLOWLIST POLICY VIOLATION: {admin_reason}",
                        )
                    )
                else:
                    # Session revocation (low risk, high security benefit)
                    apply_rev, roll_rev = generate_session_revoke_commands(ioc.value)
                    action_rev = ContainmentActionItem(
                        action_type="revoke_sessions",
                        target=ioc.value,
                        rationale="Invalidate active user sessions and refresh tokens to prevent ongoing access.",
                        risk_level="low",
                        reversible=False,
                        command_text=apply_rev,
                        rollback_command=roll_rev,
                        is_recommended=input_data.severity in ("Medium", "High", "Critical"),
                    )
                    actions.append(action_rev)
                    if action_rev.is_recommended:
                        recommended_indices.append(len(actions) - 1)

                    # Account lock (if High or Critical severity)
                    if input_data.severity in ("High", "Critical"):
                        apply_lock, roll_lock = generate_account_lock_commands(ioc.value)
                        action_lock = ContainmentActionItem(
                            action_type="lock_account",
                            target=ioc.value,
                            rationale=f"Isolate user account due to confirmed {input_data.incident_type}.",
                            risk_level="medium",
                            reversible=True,
                            command_text=apply_lock,
                            rollback_command=roll_lock,
                            is_recommended=True,
                        )
                        actions.append(action_lock)
                        recommended_indices.append(len(actions) - 1)

        # 4. Phishing Email Quarantine
        if input_data.incident_type in ("credential_phishing", "ceo_fraud", "phishing_email"):
            for ioc in input_data.iocs:
                if ioc.ioc_type == "email":
                    apply_q, roll_q = generate_email_commands(ioc.value)
                    action_q = ContainmentActionItem(
                        action_type="quarantine_email",
                        target=ioc.value,
                        rationale="Quarantine sender address and purge from recipient mailboxes.",
                        risk_level="low",
                        reversible=True,
                        command_text=apply_q,
                        rollback_command=roll_q,
                        is_recommended=True,
                    )
                    actions.append(action_q)
                    recommended_indices.append(len(actions) - 1)
                    break

        return ContainmentOutput(
            actions=actions,
            warnings=warnings,
            recommended_action_indices=recommended_indices,
        )
