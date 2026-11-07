"""Shared pytest setup.

The environment is prepared BEFORE any `app` module is imported, so tests never
use the real API key from `.env` (the container receives it as an env var).
"""
import os
import secrets

# Fresh random fake key for every test run. Tests that need it import TEST_API_KEY.
TEST_API_KEY = secrets.token_hex(16)

os.environ["APP_ENV"] = "test"
os.environ["INGEST_API_KEY"] = TEST_API_KEY

# Only fill these in when missing (inside Compose they point at the real `db`
# service; on a bare machine they are harmless dummies).
os.environ.setdefault("POSTGRES_USER", "test_user")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password-fake")
os.environ.setdefault("POSTGRES_DB", "test_db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

import app.db  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402
from tests.db_support import build_postgres_engine, build_sqlite_engine, reset_schema  # noqa: E402

AUTH = {"X-API-Key": TEST_API_KEY}


@pytest.fixture(scope="session")
def _postgres_base_engine():
    """One engine for the whole run, pointing at the dedicated <POSTGRES_DB>_test database."""
    engine = build_postgres_engine(get_settings())
    yield engine
    engine.dispose()


@pytest.fixture
def pg_engine(_postgres_base_engine):
    """PostgreSQL test engine with a fresh, empty schema (test database only)."""
    reset_schema(_postgres_base_engine, get_settings().postgres_db)
    return _postgres_base_engine


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)])
def engine(request):
    """Every test using this fixture runs on in-memory SQLite AND on real PostgreSQL."""
    if request.param == "sqlite":
        sqlite_engine = build_sqlite_engine()
        reset_schema(sqlite_engine)
        yield sqlite_engine
        sqlite_engine.dispose()
    else:
        yield request.getfixturevalue("pg_engine")


@pytest.fixture
def session(engine):
    with Session(engine) as db_session:
        yield db_session


@pytest.fixture
def client(engine, monkeypatch):
    """HTTP client for the real application, wired to the test engine.

    The real `get_db` dependency is used (not an override): only the engine behind it is swapped.
    Unhandled server errors become 500 responses instead of raising into the test.
    """
    monkeypatch.setattr(app.db, "get_engine", lambda: engine)
    application = create_app(run_startup=False)
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client
