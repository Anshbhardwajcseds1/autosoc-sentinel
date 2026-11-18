"""
Generate realistic simulated security events for testing.

Produces phishing emails, auth logs, and malware alerts with
both malicious and benign samples to test false positives.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _random_ip(malicious: bool = True) -> str:
    if malicious:
        first_octet = random.choice([45, 91, 103, 185, 193, 198, 203, 212])
        return f"{first_octet}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.choice([8, 13, 20, 34, 52])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _random_domain(malicious: bool = True) -> str:
    if malicious:
        tlds = [".xyz", ".top", ".club", ".buzz", ".ml"]
        words = ["secure-login", "account-verify", "paypal-auth", "microsoft-365-reset",
                 "urgent-action", "bank-secure", "docs-share", "invoice-pay"]
        return f"{random.choice(words)}-{random.randint(100,999)}{random.choice(tlds)}"
    return random.choice(["google.com", "microsoft.com", "github.com", "amazon.com", "slack.com"])


def _random_hash() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex[:32]


def _random_email(malicious: bool = True) -> str:
    if malicious:
        domain = _random_domain(malicious=True)
        names = ["support", "admin", "security", "noreply", "billing"]
        return f"{random.choice(names)}@{domain}"
    return random.choice([
        "newsletter@company.com",
        "hr@internal-corp.com",
        "alice.smith@partner.org",
    ])


def _random_username() -> str:
    first = random.choice(["john", "jane", "bob", "alice", "carlos", "sarah", "mike", "emma"])
    last = random.choice(["smith", "jones", "wilson", "brown", "davis", "taylor", "clark"])
    return f"{first}.{last}"


# ═══════════════════════════════════════════════════════════════
# PHISHING EMAIL TEMPLATES
# ═══════════════════════════════════════════════════════════════

def generate_phishing_ceo_fraud() -> dict:
    """CEO fraud / wire transfer request."""
    attacker_email = _random_email(malicious=True)
    attacker_ip = _random_ip(malicious=True)
    target = _random_username()
    amount = random.randint(5000, 50000)

    raw = f"""From: CEO John Davidson <{attacker_email}>
To: {target}@company.com
Subject: Urgent: Wire Transfer Needed Today
Date: {_now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Message-ID: <{uuid.uuid4().hex[:16]}@{_random_domain(True)}>
Received: from mail.{_random_domain(True)} ({attacker_ip}) by mx.company.com
X-SPF-Result: fail
X-DKIM-Result: fail
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

Hi {target},

I need you to process an urgent wire transfer of ${amount:,} to our new vendor immediately.
This is time-sensitive and confidential - please don't discuss with anyone else.

Wire to:
Bank: First National Bank
Account: {random.randint(10000000, 99999999)}
Routing: {random.randint(100000000, 999999999)}

Please confirm once completed.

Thanks,
John Davidson
CEO, Company Inc.

Sent from my iPhone"""

    return {
        "event_type": "phishing_email",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "ceo_fraud",
        "is_malicious": True,
    }


def generate_phishing_credential_harvest() -> dict:
    """Credential harvesting with fake login page."""
    attacker_email = _random_email(malicious=True)
    attacker_ip = _random_ip(malicious=True)
    phishing_domain = _random_domain(malicious=True)
    target = _random_username()

    raw = f"""From: IT Security Team <{attacker_email}>
To: {target}@company.com
Subject: [ACTION REQUIRED] Password Expiration Notice
Date: {_now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Message-ID: <{uuid.uuid4().hex[:16]}@{_random_domain(True)}>
Received: from smtp.{_random_domain(True)} ({attacker_ip}) by mx.company.com
X-SPF-Result: softfail
X-DKIM-Result: fail
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

Dear {target},

Your password will expire in 24 hours. To avoid being locked out, please update your password immediately:

https://{phishing_domain}/login?user={target}@company.com&token={uuid.uuid4().hex[:8]}

If you do not update your password, your account will be suspended.

This is an automated message from IT Security.
Do not reply to this email.

IT Security Team
Company Inc."""

    return {
        "event_type": "phishing_email",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "credential_phishing",
        "is_malicious": True,
    }


def generate_phishing_malware_attachment() -> dict:
    """Malware attachment (fake invoice)."""
    attacker_email = _random_email(malicious=True)
    attacker_ip = _random_ip(malicious=True)
    malware_hash = _random_hash()
    target = _random_username()

    raw = f"""From: Accounts Payable <{attacker_email}>
To: {target}@company.com
Subject: Invoice #INV-{random.randint(10000,99999)} - Payment Due
Date: {_now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Message-ID: <{uuid.uuid4().hex[:16]}@{_random_domain(True)}>
Received: from relay.{_random_domain(True)} ({attacker_ip}) by mx.company.com
X-SPF-Result: none
X-DKIM-Result: none
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary_{uuid.uuid4().hex[:8]}"
X-Attachment-Hash-SHA256: {malware_hash}

Please find attached invoice for your records.
Payment is due within 5 business days.

Attachment: Invoice_{random.randint(10000,99999)}.pdf.exe (SHA256: {malware_hash})

Best regards,
Accounting Department"""

    return {
        "event_type": "phishing_email",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "malware_attachment",
        "is_malicious": True,
    }


def generate_phishing_internal_spoof() -> dict:
    """Spear-phishing with spoofed internal domain."""
    attacker_ip = _random_ip(malicious=True)
    target = _random_username()
    spoofed_domain = "company.com"
    actual_domain = _random_domain(malicious=True)
    phishing_url = f"https://{_random_domain(True)}/share/{uuid.uuid4().hex[:12]}"

    raw = f"""From: HR Department <hr@{spoofed_domain}>
To: {target}@company.com
Subject: Updated Employee Handbook - Please Review
Date: {_now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Message-ID: <{uuid.uuid4().hex[:16]}@{actual_domain}>
Received: from mail.{actual_domain} ({attacker_ip}) by mx.company.com
X-SPF-Result: fail
X-DKIM-Result: fail
Return-Path: bounce@{actual_domain}
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

Hi {target},

The updated employee handbook is now available. Please review the changes that affect your department:

{phishing_url}

You must acknowledge receipt by end of day Friday.

Thanks,
Human Resources"""

    return {
        "event_type": "phishing_email",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "internal_spoof",
        "is_malicious": True,
    }


def generate_benign_email() -> dict:
    """Benign marketing / newsletter email (false positive test)."""
    target = _random_username()
    sender_ip = _random_ip(malicious=False)

    raw = f"""From: GitHub <noreply@github.com>
To: {target}@company.com
Subject: [GitHub] Your weekly digest
Date: {_now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Message-ID: <{uuid.uuid4().hex[:16]}@github.com>
Received: from out-1.smtp.github.com ({sender_ip}) by mx.company.com
X-SPF-Result: pass
X-DKIM-Result: pass
List-Unsubscribe: <https://github.com/settings/notifications>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

Hi {target},

Here's your weekly summary of activity on repositories you're watching:

- 3 new pull requests in org/frontend-app
- 12 commits to org/backend-service
- 1 new release: v2.4.1 of org/shared-lib

View full digest: https://github.com/notifications

Thanks,
The GitHub Team"""

    return {
        "event_type": "phishing_email",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "benign_email",
        "is_malicious": False,
    }


# ═══════════════════════════════════════════════════════════════
# AUTH LOG TEMPLATES
# ═══════════════════════════════════════════════════════════════

def generate_auth_brute_force() -> dict:
    """Brute-force: 50+ failed logins from one IP."""
    attacker_ip = _random_ip(malicious=True)
    target_user = _random_username()
    base_time = _now() - timedelta(minutes=5)

    lines = []
    for i in range(random.randint(50, 80)):
        ts = base_time + timedelta(seconds=i * random.uniform(2, 8))
        lines.append(
            f'{ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH FAILED user={target_user} '
            f'src_ip={attacker_ip} method=password reason=invalid_password '
            f'attempt={i+1} user_agent="Mozilla/5.0"'
        )
    # Final success after brute force
    ts = base_time + timedelta(minutes=6)
    lines.append(
        f'{ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH SUCCESS user={target_user} '
        f'src_ip={attacker_ip} method=password mfa=false '
        f'user_agent="Mozilla/5.0" geo=RU,Moscow'
    )

    return {
        "event_type": "auth_log",
        "raw_content": "\n".join(lines),
        "source": "simulator",
        "scenario": "brute_force",
        "is_malicious": True,
    }


def generate_auth_impossible_travel() -> dict:
    """Impossible travel: logins from US and Russia within 10 min."""
    user = _random_username()
    ip_us = _random_ip(malicious=False)
    ip_ru = _random_ip(malicious=True)
    t1 = _now() - timedelta(minutes=10)
    t2 = _now()

    raw = f"""{t1.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH SUCCESS user={user} src_ip={ip_us} method=password mfa=true geo=US,New_York device=known_laptop user_agent="Chrome/120.0"
{t2.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH SUCCESS user={user} src_ip={ip_ru} method=password mfa=false geo=RU,Moscow device=unknown user_agent="Firefox/119.0" """

    return {
        "event_type": "auth_log",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "impossible_travel",
        "is_malicious": True,
    }


def generate_auth_credential_stuffing() -> dict:
    """Credential stuffing: failed logins across many accounts from one IP."""
    attacker_ip = _random_ip(malicious=True)
    base_time = _now() - timedelta(minutes=3)

    lines = []
    for i in range(random.randint(30, 50)):
        user = _random_username()
        ts = base_time + timedelta(seconds=i * random.uniform(1, 4))
        lines.append(
            f'{ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH FAILED user={user} '
            f'src_ip={attacker_ip} method=password reason=invalid_credentials '
            f'user_agent="python-requests/2.31.0"'
        )

    return {
        "event_type": "auth_log",
        "raw_content": "\n".join(lines),
        "source": "simulator",
        "scenario": "credential_stuffing",
        "is_malicious": True,
    }


def generate_auth_normal_login() -> dict:
    """Normal login from known location (benign)."""
    user = _random_username()
    ip = _random_ip(malicious=False)
    ts = _now()

    raw = f"""{ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH SUCCESS user={user} src_ip={ip} method=sso mfa=true geo=US,San_Francisco device=known_laptop user_agent="Chrome/120.0.6099.129" session_id={uuid.uuid4().hex[:16]}"""

    return {
        "event_type": "auth_log",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "normal_login",
        "is_malicious": False,
    }


def generate_auth_afterhours() -> dict:
    """After-hours login from new device (medium suspicion)."""
    user = _random_username()
    ip = _random_ip(malicious=False)
    ts = _now().replace(hour=3, minute=random.randint(0, 59))

    raw = f"""{ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")} AUTH SUCCESS user={user} src_ip={ip} method=password mfa=false geo=US,Austin device=unknown user_agent="Safari/17.2" session_id={uuid.uuid4().hex[:16]} first_seen_device=true login_hour=03"""

    return {
        "event_type": "auth_log",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "afterhours_login",
        "is_malicious": False,
    }


# ═══════════════════════════════════════════════════════════════
# MALWARE ALERT TEMPLATES
# ═══════════════════════════════════════════════════════════════

def generate_malware_known_bad() -> dict:
    """Alert with a known-bad file hash."""
    malware_hash_sha256 = _random_hash()
    malware_hash_md5 = uuid.uuid4().hex
    user = _random_username()
    ip = _random_ip(malicious=False)
    ts = _now()

    raw = f"""MALWARE_ALERT timestamp={ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")}
host={user}-workstation src_ip={ip} user={user}
file_name=Q4_Report_Final.pdf.exe
file_path=C:\\Users\\{user}\\Downloads\\Q4_Report_Final.pdf.exe
file_size=2847193
sha256={malware_hash_sha256}
md5={malware_hash_md5}
detection=Trojan.GenericKD.{random.randint(10000,99999)}
action=quarantined
av_engine=CrowdStrike Falcon
confidence=high"""

    return {
        "event_type": "malware_alert",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "known_malware",
        "is_malicious": True,
    }


def generate_malware_clean() -> dict:
    """Alert with a clean file hash (false positive test)."""
    clean_hash = _random_hash()
    user = _random_username()
    ip = _random_ip(malicious=False)
    ts = _now()

    raw = f"""MALWARE_ALERT timestamp={ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")}
host={user}-workstation src_ip={ip} user={user}
file_name=quarterly-report.pdf
file_path=C:\\Users\\{user}\\Downloads\\quarterly-report.pdf
file_size=524288
sha256={clean_hash}
md5={uuid.uuid4().hex}
detection=Heuristic.Suspicious
action=allowed
av_engine=Windows Defender
confidence=low"""

    return {
        "event_type": "malware_alert",
        "raw_content": raw,
        "source": "simulator",
        "scenario": "clean_file",
        "is_malicious": False,
    }


# ═══════════════════════════════════════════════════════════════
# GENERATOR REGISTRY
# ═══════════════════════════════════════════════════════════════

GENERATORS = {
    "phishing_email": {
        "ceo_fraud": generate_phishing_ceo_fraud,
        "credential_phishing": generate_phishing_credential_harvest,
        "malware_attachment": generate_phishing_malware_attachment,
        "internal_spoof": generate_phishing_internal_spoof,
        "benign_email": generate_benign_email,
    },
    "auth_log": {
        "brute_force": generate_auth_brute_force,
        "impossible_travel": generate_auth_impossible_travel,
        "credential_stuffing": generate_auth_credential_stuffing,
        "normal_login": generate_auth_normal_login,
        "afterhours_login": generate_auth_afterhours,
    },
    "malware_alert": {
        "known_malware": generate_malware_known_bad,
        "clean_file": generate_malware_clean,
    },
}

ALL_SCENARIOS = []
for event_type, scenarios in GENERATORS.items():
    for scenario_name in scenarios:
        ALL_SCENARIOS.append((event_type, scenario_name))


def generate_event(
    event_type: Optional[str] = None,
    scenario: Optional[str] = None,
) -> dict:
    """
    Generate a single simulated event.

    Args:
        event_type: "phishing_email", "auth_log", or "malware_alert". Random if None.
        scenario: Specific scenario name. Random (from type) if None.

    Returns:
        Dict with event_type, raw_content, source, scenario, is_malicious
    """
    if event_type is None:
        event_type = random.choice(list(GENERATORS.keys()))

    if event_type not in GENERATORS:
        raise ValueError(f"Unknown event type: {event_type}. Choose from: {list(GENERATORS.keys())}")

    type_scenarios = GENERATORS[event_type]

    if scenario is None:
        scenario = random.choice(list(type_scenarios.keys()))

    if scenario not in type_scenarios:
        raise ValueError(f"Unknown scenario '{scenario}' for {event_type}. Choose from: {list(type_scenarios.keys())}")

    return type_scenarios[scenario]()


def generate_batch(
    count: int = 10,
    event_type: Optional[str] = None,
    scenario: Optional[str] = None,
) -> list[dict]:
    """Generate multiple simulated events."""
    return [generate_event(event_type, scenario) for _ in range(count)]
