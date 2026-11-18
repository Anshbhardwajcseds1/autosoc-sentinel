"""Log-Analyzer Agent: Deterministic regex IOC extraction + contextual LLM analysis."""

from __future__ import annotations

import logging
import re
from typing import List, Set
from urllib.parse import urlparse

from app.agents.base import BaseAgent
from app.models.schemas import (
    IOCItem,
    LLMAnalysis,
    LogAnalyzerInput,
    LogAnalyzerOutput,
)
from app.services.llm_service import LLMProvider, get_llm_provider

logger = logging.getLogger(__name__)

# ── Extraction Regexes ───────────────────────────────────────

# IPv4 (including defanged 192[.]168[.]1[.]1)
IPV4_REGEX = re.compile(
    r"\b(?:[0-9]{1,3}(?:\[\.\]|\.)){3}[0-9]{1,3}\b"
)

# Email address
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:\[\.\]|\.)[A-Za-z]{2,}\b"
)

# URLs (including hxxp://, hxxps://, and defanged [:])
URL_REGEX = re.compile(
    r"(?:https?|hxxps?):\/\/[^\s<>\"\'\)]+",
    re.IGNORECASE,
)

# Hashes: MD5 (32), SHA1 (40), SHA256 (64)
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Auth logs patterns
USER_PATTERN_1 = re.compile(r"\buser=([a-zA-Z0-9._-]+)\b", re.IGNORECASE)
USER_PATTERN_2 = re.compile(r"\bTo:\s*([a-zA-Z0-9._-]+)@\b", re.IGNORECASE)


def refang(text: str) -> str:
    """Normalize defanged indicators (e.g. 1[.]1[.]1[.]1 -> 1.1.1.1, hxxp -> http)."""
    text = text.replace("[.]", ".").replace("[:]", ":")
    if text.startswith("hxxp://"):
        text = "http://" + text[7:]
    elif text.startswith("hxxps://"):
        text = "https://" + text[8:]
    return text


def is_valid_ipv4(ip_str: str) -> bool:
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


class LogAnalyzerAgent(BaseAgent[LogAnalyzerInput, LogAnalyzerOutput]):
    """Analyzes raw emails, authentication logs, and alerts."""

    name = "log_analyzer"

    def __init__(self, llm: LLMProvider | None = None):
        self.llm = llm or get_llm_provider()

    def extract_iocs(self, content: str) -> list[IOCItem]:
        """Deterministic extraction of indicators of compromise from raw content."""
        iocs: list[IOCItem] = []
        seen: Set[tuple[str, str]] = set()

        def add_ioc(ioc_type: str, val: str, ctx: str = ""):
            cleaned = refang(val.strip().strip(",;\"'<>"))
            key = (ioc_type, cleaned.lower())
            if key not in seen and cleaned:
                seen.add(key)
                iocs.append(IOCItem(ioc_type=ioc_type, value=cleaned, context=ctx))

        # 1. IPs
        for match in IPV4_REGEX.finditer(content):
            ip_val = refang(match.group(0))
            if is_valid_ipv4(ip_val):
                add_ioc("ip", ip_val, "Network traffic / log IP")

        # 2. URLs & extracted domains
        for match in URL_REGEX.finditer(content):
            raw_url = match.group(0)
            clean_url = refang(raw_url)
            add_ioc("url", clean_url, "Embedded link")

            try:
                parsed = urlparse(clean_url)
                if parsed.hostname and not is_valid_ipv4(parsed.hostname):
                    add_ioc("domain", parsed.hostname, f"Domain from URL: {clean_url}")
            except Exception:
                pass

        # 3. Emails & domain extraction
        for match in EMAIL_REGEX.finditer(content):
            email_val = refang(match.group(0))
            add_ioc("email", email_val, "Email address reference")
            if "@" in email_val:
                domain_part = email_val.split("@")[1].strip("[]")
                if domain_part and "." in domain_part and not is_valid_ipv4(domain_part):
                    add_ioc("domain", domain_part, f"Domain from email: {email_val}")

        # 4. Hashes (check SHA256 first, then SHA1, then MD5 to avoid prefix collisions)
        found_sha256 = set()
        for match in SHA256_REGEX.finditer(content):
            val = match.group(0).lower()
            found_sha256.add(val)
            add_ioc("hash_sha256", val, "SHA-256 file hash")

        found_sha1 = set()
        for match in SHA1_REGEX.finditer(content):
            val = match.group(0).lower()
            # ensure not substring of already captured sha256
            if not any(val in s for s in found_sha256):
                found_sha1.add(val)
                add_ioc("hash_sha1", val, "SHA-1 file hash")

        for match in MD5_REGEX.finditer(content):
            val = match.group(0).lower()
            if not any(val in s for s in found_sha256) and not any(val in s for s in found_sha1):
                add_ioc("hash_md5", val, "MD5 file hash")

        # 5. Usernames
        for match in USER_PATTERN_1.finditer(content):
            add_ioc("username", match.group(1), "User account in auth log")
        for match in USER_PATTERN_2.finditer(content):
            add_ioc("username", match.group(1), "Target recipient user")

        return iocs

    async def run(self, input_data: LogAnalyzerInput) -> LogAnalyzerOutput:
        """Run extraction and contextual LLM analysis with anti-injection safeguards."""
        logger.info("LogAnalyzerAgent analyzing event: %s (%s)", input_data.event_id, input_data.event_type)

        # 1. Deterministic extraction
        extracted_iocs = self.extract_iocs(input_data.raw_content)

        # 2. Prepare delimited untrusted content for LLM
        system_prompt = (
            "You are a Tier 2 SOC Analyst specializing in email threat analysis and log forensics. "
            "Analyze the provided security event telemetry. "
            "Identify: spoofed headers, SPF/DKIM validation failures, impossible travel anomalies, "
            "brute-force patterns, urgency or financial coercion, credential harvesting, "
            "and classify the primary incident type."
        )

        user_prompt = (
            f"Event Type: {input_data.event_type}\n"
            f"Extracted Indicators ({len(extracted_iocs)} found):\n"
            + "\n".join(f"- {i.ioc_type}: {i.value}" for i in extracted_iocs[:15])
            + "\n\n"
            "<<<UNTRUSTED_EVENT_CONTENT>>>\n"
            f"{input_data.raw_content}\n"
            "<<<END_UNTRUSTED_EVENT_CONTENT>>>"
        )

        try:
            llm_result: LLMAnalysis = await self.llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                schema_class=LLMAnalysis,
            )
        except Exception as e:
            logger.error("LLM analysis failed in LogAnalyzer: %s", e)
            llm_result = LLMAnalysis(
                summary=f"Automated analysis based on {len(extracted_iocs)} extracted IOCs.",
                incident_type=input_data.event_type,
                confidence=0.5,
                reasoning="Fallback heuristic summary (LLM unavailable).",
            )

        return LogAnalyzerOutput(
            iocs=extracted_iocs,
            summary=llm_result.summary,
            incident_type=llm_result.incident_type or input_data.event_type,
            llm_analysis=llm_result,
            confidence=llm_result.confidence,
        )
