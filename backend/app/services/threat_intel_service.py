"""Threat intelligence service: VirusTotal, AbuseIPDB, SQLite caching, and realistic mock mode."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models.db_models import ThreatIntelCache
from app.models.schemas import IOCItem, IOCThreatResult, Severity

logger = logging.getLogger(__name__)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to RFC 1918 or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


class ThreatIntelService:
    """Provides IOC enrichment with caching and mock capability."""

    def __init__(self, db_session: Optional[Session] = None):
        self.settings = get_settings()
        self.db = db_session

    def _get_db(self) -> Session:
        if self.db is not None:
            return self.db
        return SessionLocal()

    def get_cached(self, ioc_type: str, ioc_value: str, source: str) -> Optional[ThreatIntelCache]:
        """Check local SQLite cache for unexpired result."""
        db = self._get_db()
        try:
            entry = (
                db.query(ThreatIntelCache)
                .filter(
                    ThreatIntelCache.ioc_type == ioc_type,
                    ThreatIntelCache.ioc_value == ioc_value,
                    ThreatIntelCache.source == source,
                )
                .first()
            )
            if entry:
                age_seconds = (datetime.now(timezone.utc) - entry.cached_at.replace(tzinfo=timezone.utc)).total_seconds()
                if age_seconds < entry.ttl_seconds:
                    return entry
            return None
        finally:
            if self.db is None:
                db.close()

    def set_cache(
        self,
        ioc_type: str,
        ioc_value: str,
        source: str,
        response_data: dict[str, Any],
        reputation_score: float,
        malicious: bool,
        ttl_seconds: int = 86400,
    ) -> None:
        """Store result in SQLite cache."""
        db = self._get_db()
        try:
            entry = ThreatIntelCache(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                source=source,
                response_data=response_data,
                reputation_score=reputation_score,
                malicious=malicious,
                ttl_seconds=ttl_seconds,
            )
            db.merge(entry)
            db.commit()
        except Exception as e:
            logger.warning("Failed to cache threat intel result: %s", e)
            db.rollback()
        finally:
            if self.db is None:
                db.close()

    def mock_lookup(self, ioc: IOCItem) -> list[IOCThreatResult]:
        """Generate realistic mock reputation for any IOC."""
        results = []
        val = ioc.value.lower()

        if ioc.ioc_type == "ip":
            # Check private ranges
            if is_private_ip(ioc.value):
                reputation = 0.0
                malicious = False
                source = "mock"
                details = {"category": "private_network", "reports": 0, "country": "Local"}
            else:
                # Malicious simulator IP octets: 45, 91, 103, 185, 193, 198, 203, 212
                first_octet = int(ioc.value.split(".")[0]) if "." in ioc.value else 0
                if first_octet in (45, 91, 103, 185, 193, 198, 203, 212):
                    reputation = 88.0 + (first_octet % 11)
                    malicious = True
                    details = {
                        "abuse_confidence_score": reputation,
                        "reports": 42,
                        "last_reported": "2026-11-18",
                        "country": "RU",
                        "isp": "HostKey Ltd",
                    }
                else:
                    reputation = 2.0
                    malicious = False
                    details = {"abuse_confidence_score": 0, "reports": 0, "country": "US", "isp": "Cloudflare"}

            results.append(
                IOCThreatResult(
                    ioc_type="ip",
                    ioc_value=ioc.value,
                    source="mock",
                    reputation_score=min(100.0, reputation),
                    malicious=malicious,
                    details=details,
                )
            )

        elif ioc.ioc_type in ("domain", "url"):
            # Check domain / url suspicious indicators
            suspicious_words = [
                "secure-login", "account-verify", "paypal", "microsoft-365",
                "urgent-action", "bank-secure", "invoice", ".xyz", ".top", ".club",
            ]
            is_suspicious = any(w in val for w in suspicious_words)
            trusted_domains = ["google.com", "microsoft.com", "github.com", "amazon.com", "slack.com"]
            is_trusted = any(td in val for td in trusted_domains)

            if is_trusted:
                reputation = 0.0
                malicious = False
                details = {"vt_positives": 0, "category": "legitimate_service"}
            elif is_suspicious:
                reputation = 94.0
                malicious = True
                details = {"vt_positives": 18, "categories": ["phishing", "malicious"]}
            else:
                reputation = 15.0
                malicious = False
                details = {"vt_positives": 0, "categories": ["neutral"]}

            results.append(
                IOCThreatResult(
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.value,
                    source="mock",
                    reputation_score=reputation,
                    malicious=malicious,
                    details=details,
                )
            )

        elif ioc.ioc_type in ("hash_sha256", "hash_md5", "hash_sha1"):
            # If hash is known or ends in even char -> treat as malicious in mock
            is_mal = val.endswith(("0", "2", "4", "6", "8", "a", "c", "e"))
            reputation = 98.0 if is_mal else 0.0
            results.append(
                IOCThreatResult(
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.value,
                    source="mock",
                    reputation_score=reputation,
                    malicious=is_mal,
                    details={
                        "positives": 54 if is_mal else 0,
                        "total_scanners": 72,
                        "threat_classification": "Trojan.Agent.Dropper" if is_mal else "Clean",
                    },
                )
            )

        elif ioc.ioc_type == "email":
            domain = val.split("@")[1] if "@" in val else ""
            is_suspicious = any(w in domain for w in [".xyz", ".top", ".club", "secure", "verify"])
            reputation = 85.0 if is_suspicious else 5.0
            results.append(
                IOCThreatResult(
                    ioc_type="email",
                    ioc_value=ioc.value,
                    source="mock",
                    reputation_score=reputation,
                    malicious=is_suspicious,
                    details={"spf_valid": not is_suspicious, "disposable": is_suspicious},
                )
            )

        return results

    async def lookup_virustotal(self, ioc: IOCItem) -> Optional[IOCThreatResult]:
        """Query VirusTotal API v3."""
        if not self.settings.virustotal_api_key or self.settings.virustotal_api_key == "your-virustotal-api-key-here":
            return None

        headers = {"x-apikey": self.settings.virustotal_api_key}
        endpoint = None
        if ioc.ioc_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}"
        elif ioc.ioc_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc.value}"
        elif ioc.ioc_type in ("hash_sha256", "hash_md5", "hash_sha1"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc.value}"

        if not endpoint:
            return None

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    rep_score = min(100.0, (malicious_count / total) * 100.0 * 2.0)
                    return IOCThreatResult(
                        ioc_type=ioc.ioc_type,
                        ioc_value=ioc.value,
                        source="virustotal",
                        reputation_score=rep_score,
                        malicious=malicious_count > 2,
                        details={"stats": stats},
                    )
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", ioc.value, e)
        return None

    async def lookup_abuseipdb(self, ioc: IOCItem) -> Optional[IOCThreatResult]:
        """Query AbuseIPDB API v2."""
        if ioc.ioc_type != "ip":
            return None
        if not self.settings.abuseipdb_api_key or self.settings.abuseipdb_api_key == "your-abuseipdb-api-key-here":
            return None

        headers = {"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc.value, "maxAgeInDays": 90}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0))
                    return IOCThreatResult(
                        ioc_type="ip",
                        ioc_value=ioc.value,
                        source="abuseipdb",
                        reputation_score=score,
                        malicious=score > 25.0,
                        details=data,
                    )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ioc.value, e)
        return None

    async def enrich_ioc(self, ioc: IOCItem) -> list[IOCThreatResult]:
        """Enrich an IOC, checking cache first, then API or Mock."""
        results: list[IOCThreatResult] = []

        # Check cache
        cached = self.get_cached(ioc.ioc_type, ioc.value, "all")
        if cached:
            return [
                IOCThreatResult(
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.value,
                    source=cached.source,  # type: ignore
                    reputation_score=cached.reputation_score,
                    malicious=cached.malicious,
                    details=cached.response_data,
                    cached=True,
                )
            ]

        # In mock mode, immediately return realistic mock data
        if self.settings.mock_mode:
            results = self.mock_lookup(ioc)
        else:
            # Live lookups with fallback
            vt = await self.lookup_virustotal(ioc)
            if vt:
                results.append(vt)
            ab = await self.lookup_abuseipdb(ioc)
            if ab:
                results.append(ab)

            if not results:
                # Fallback to mock if API keys unavailable or failed
                results = self.mock_lookup(ioc)

        # Cache results
        for r in results:
            self.set_cache(
                ioc_type=r.ioc_type,
                ioc_value=r.ioc_value,
                source=r.source,
                response_data=r.details or {},
                reputation_score=r.reputation_score,
                malicious=r.malicious,
            )

        return results
