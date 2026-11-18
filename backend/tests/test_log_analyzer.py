"""Tests for Log-Analyzer Agent."""

from __future__ import annotations

import pytest

from app.agents.log_analyzer import LogAnalyzerAgent, is_valid_ipv4, refang
from app.models.schemas import LogAnalyzerInput
from app.services.llm_service import MockLLMProvider


class TestLogAnalyzerRegex:
    def setup_method(self):
        self.agent = LogAnalyzerAgent(llm=MockLLMProvider())

    def test_refang(self):
        assert refang("192[.]168[.]1[.]1") == "192.168.1.1"
        assert refang("hxxps://malicious[.]top/login") == "https://malicious.top/login"
        assert refang("hxxp://evil[.]com") == "http://evil.com"

    def test_ipv4_validation(self):
        assert is_valid_ipv4("1.1.1.1") is True
        assert is_valid_ipv4("255.255.255.255") is True
        assert is_valid_ipv4("256.1.1.1") is False
        assert is_valid_ipv4("1.2.3") is False

    def test_extract_ipv4(self):
        text = "Connection from 45.33.32.156 and defanged 185.220[.]101[.]5 on port 80"
        iocs = self.agent.extract_iocs(text)
        ips = [i.value for i in iocs if i.ioc_type == "ip"]
        assert "45.33.32.156" in ips
        assert "185.220.101.5" in ips

    def test_extract_urls_and_domains(self):
        text = "Visit https://secure-login.xyz/auth?user=test and hxxp://evil-download.top/payload.exe"
        iocs = self.agent.extract_iocs(text)
        urls = [i.value for i in iocs if i.ioc_type == "url"]
        domains = [i.value for i in iocs if i.ioc_type == "domain"]
        assert "https://secure-login.xyz/auth?user=test" in urls
        assert "http://evil-download.top/payload.exe" in urls
        assert "secure-login.xyz" in domains
        assert "evil-download.top" in domains

    def test_extract_emails(self):
        text = "Sender is attacker@phishing-domain.xyz and target is bob.smith@company.com"
        iocs = self.agent.extract_iocs(text)
        emails = [i.value for i in iocs if i.ioc_type == "email"]
        assert "attacker@phishing-domain.xyz" in emails
        assert "bob.smith@company.com" in emails

    def test_extract_hashes(self):
        md5_val = "0123456789abcdef0123456789abcdef"
        sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"Sample MD5: {md5_val} and SHA256: {sha256_val}"
        iocs = self.agent.extract_iocs(text)
        hashes_md5 = [i.value for i in iocs if i.ioc_type == "hash_md5"]
        hashes_sha256 = [i.value for i in iocs if i.ioc_type == "hash_sha256"]
        assert md5_val in hashes_md5
        assert sha256_val in hashes_sha256

    def test_extract_usernames(self):
        text = "AUTH FAILED user=alice.smith src_ip=1.2.3.4"
        iocs = self.agent.extract_iocs(text)
        users = [i.value for i in iocs if i.ioc_type == "username"]
        assert "alice.smith" in users


@pytest.mark.asyncio
class TestLogAnalyzerAgentExecution:
    async def test_run_phishing_analysis(self):
        agent = LogAnalyzerAgent(llm=MockLLMProvider())
        content = (
            "From: CEO John <ceo@external.com>\n"
            "To: finance@company.com\n"
            "Subject: Urgent Wire Transfer\n"
            "Please wire $25,000 immediately to account 123456789."
        )
        inp = LogAnalyzerInput(
            event_id="test-1",
            event_type="phishing_email",
            raw_content=content,
        )
        out, duration = await agent.execute(inp)
        assert out.summary != ""
        assert out.confidence > 0.8
        assert out.llm_analysis is not None
        assert out.llm_analysis.urgency_language is True
        assert duration >= 0
