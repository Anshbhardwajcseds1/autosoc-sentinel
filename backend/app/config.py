"""Application configuration loaded from environment variables."""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from typing import List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration is loaded from .env or environment variables."""

    # LLM
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    # Threat Intelligence
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Mode
    mock_mode: bool = True
    llm_mock_mode: bool = True

    # Database
    database_url: str = "sqlite:///./autosoc.db"

    # Logging
    log_level: str = "INFO"

    # CORS
    cors_origins: Union[List[str], str] = ["http://localhost:5173", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [s.strip() for s in v.split(",") if s.strip()]
        return v

    # Allowlist
    analyst_ips: Union[List[str], str] = []

    @field_validator("analyst_ips", mode="before")
    @classmethod
    def parse_analyst_ips(cls, v):
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    admin_accounts: Union[List[str], str] = ["admin", "soc-admin", "service-account"]

    @field_validator("admin_accounts", mode="before")
    @classmethod
    def parse_admin_accounts(cls, v):
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Private network ranges that must never be blocked
    @property
    def private_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
            ipaddress.IPv4Network("127.0.0.0/8"),
            ipaddress.IPv6Network("::1/128"),
            ipaddress.IPv6Network("fe80::/10"),
        ]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()
