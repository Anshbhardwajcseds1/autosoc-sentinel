"""Shared test fixtures."""

from __future__ import annotations

import os
import pytest

# Force test settings before any app imports
os.environ["DATABASE_URL"] = "sqlite:///./test_autosoc.db"
os.environ["MOCK_MODE"] = "true"
os.environ["LLM_MOCK_MODE"] = "true"
os.environ["GEMINI_API_KEY"] = "test-key"

from app.config import Settings, get_settings
from app.database import Base, engine, SessionLocal, init_db


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """Clear cached settings between tests."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def db_session():
    """Provide a clean database session for each test."""
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
