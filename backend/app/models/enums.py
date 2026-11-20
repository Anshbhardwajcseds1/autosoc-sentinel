"""Named string constants for domain types used across the AutoSOC pipeline.

These Enums match the Literal types in schemas.py and the string column values
stored in the SQLite database, ensuring consistent usage across agents, services,
and API layers.
"""

from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    """Supported raw event types ingested by the pipeline."""

    PHISHING_EMAIL = "phishing_email"
    AUTH_LOG = "auth_log"
    MALWARE_ALERT = "malware_alert"


class IncidentStatus(str, Enum):
    """Lifecycle states of a security incident."""

    ANALYZING = "analyzing"
    AWAITING_REVIEW = "awaiting_review"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class Severity(str, Enum):
    """Overall severity assigned to an incident after threat-intel enrichment."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IOCType(str, Enum):
    """Supported indicator-of-compromise types extracted by the Log-Analyzer."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    USERNAME = "username"


class ActionType(str, Enum):
    """Containment action types proposed by the Containment Agent (never executed against real systems)."""

    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_EMAIL = "quarantine_email"
    LOCK_ACCOUNT = "lock_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    REVOKE_SESSIONS = "revoke_sessions"


class ActionStatus(str, Enum):
    """Lifecycle states of a proposed containment action."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED_SIMULATED = "executed_simulated"
    ROLLED_BACK = "rolled_back"


class RiskLevel(str, Enum):
    """Risk level assigned to a proposed containment action."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IntelSource(str, Enum):
    """Threat intelligence data sources queried by the Threat-Intel Agent."""

    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    MOCK = "mock"
