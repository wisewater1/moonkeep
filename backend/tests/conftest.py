"""Shared pytest fixtures for Moonkeep backend tests."""

import os
import sys
import tempfile
import pytest

# Ensure the backend package root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Point auth + campaign DBs at temp files BEFORE importing anything else
_auth_tmp = tempfile.NamedTemporaryFile(suffix="_auth.db", delete=False)
_campaign_tmp = tempfile.NamedTemporaryFile(suffix="_campaigns.db", delete=False)
os.environ["MOONKEEP_AUTH_DB"] = _auth_tmp.name
_auth_tmp.close()
_campaign_tmp.close()

# Now safe to import app and auth helpers
from core.auth import init_auth_db, create_token, SECRET_KEY, ALGORITHM
from core.campaign_manager import CampaignManager
from fastapi.testclient import TestClient
from main import app, limiter


# Disable rate limiting for the entire test suite so login-heavy tests don't 429.
limiter.enabled = False


@pytest.fixture(scope="session", autouse=True)
def _bootstrap_auth_db():
    """Create the default admin user once for the whole test session."""
    init_auth_db()


@pytest.fixture()
def client():
    """FastAPI TestClient wired to the app."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_token():
    """Return a valid JWT for the admin user (no network call needed)."""
    return create_token("admin", "admin")


@pytest.fixture()
def auth_headers(auth_token):
    """Return headers dict with a valid Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture()
def campaign_manager(tmp_path):
    """CampaignManager backed by a disposable temp DB."""
    db_path = str(tmp_path / "test_campaigns.db")
    return CampaignManager(db_path=db_path)


# ── Cleanup ─────────────────────────────────────────────────────
def pytest_sessionfinish(session, exitstatus):
    """Remove temporary DB files after the full test run."""
    for path in (_auth_tmp.name, _campaign_tmp.name):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(path + suffix)
            except FileNotFoundError:
                pass
