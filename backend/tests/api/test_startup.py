"""What happens when the real application starts (lifespan with run_startup=True)."""
import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import inspect

import app.db
from app.config import get_settings
from app.logging_config import HANDLER_ATTR
from app.main import create_app
from tests.db_support import build_sqlite_engine

FAKE_PASSWORD = "startup-test-password-fake"


@pytest.fixture(autouse=True)
def restore_state():
    root = logging.getLogger()
    saved = (root.handlers[:], root.level)
    get_settings.cache_clear()
    yield
    root.handlers[:] = saved[0]
    root.setLevel(saved[1])
    get_settings.cache_clear()


@pytest.mark.parametrize("bad_key", ["change-me", "short", "aaaaaaaaaaaaaaaaaaaaaaaa"])
def test_app_refuses_to_start_with_a_missing_weak_or_placeholder_api_key(monkeypatch, bad_key):
    monkeypatch.setenv("INGEST_API_KEY", bad_key)
    with pytest.raises(ValidationError):
        with TestClient(create_app(run_startup=True)):
            pass


def test_app_refuses_to_start_without_an_api_key(monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY")
    with pytest.raises(ValidationError):
        with TestClient(create_app(run_startup=True)):
            pass


def test_startup_creates_tables_and_installs_secret_redacting_logging(monkeypatch, capsys):
    engine = build_sqlite_engine()
    monkeypatch.setattr(app.db, "get_engine", lambda: engine)
    monkeypatch.setenv("POSTGRES_PASSWORD", FAKE_PASSWORD)
    with TestClient(create_app(run_startup=True)):
        assert set(inspect(engine).get_table_names()) == {
            "events", "indicators", "event_indicators", "incidents", "incident_events"}
        assert any(getattr(h, HANDLER_ATTR, False) for h in logging.getLogger().handlers)
        logging.getLogger("startup-test").warning("leak attempt: %s", FAKE_PASSWORD)
    err = capsys.readouterr().err
    assert "leak attempt: ***" in err
    assert FAKE_PASSWORD not in err
    assert "ThreatScope API started" in err
