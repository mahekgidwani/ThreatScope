"""app.db: engine factory, session dependency, schema creation and health check."""
import logging

import pytest
from sqlalchemy import select, func
from sqlalchemy.orm import Session

import app.db as db
from app.db import check_db, get_db, get_engine, init_db, make_engine
from app.models import Event


def test_check_db_reports_ok_with_latency(engine):
    ok, latency_ms = check_db(engine)
    assert ok is True
    assert isinstance(latency_ms, float) and latency_ms >= 0


def test_check_db_never_raises_and_never_logs_credentials(caplog):
    bad = make_engine("postgresql+psycopg://u:pw-FAKE-123@127.0.0.1:1/x")
    with caplog.at_level(logging.DEBUG):
        ok, latency_ms = check_db(bad)
    assert (ok, latency_ms) == (False, None)
    assert "pw-FAKE-123" not in caplog.text
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_make_engine_sets_connect_timeout_for_postgres_only(monkeypatch):
    captured = {}

    def fake_create_engine(url, **kwargs):
        captured[url.get_backend_name()] = kwargs
        return object()

    monkeypatch.setattr(db, "create_engine", fake_create_engine)
    make_engine("postgresql+psycopg://u:p@h/d")
    make_engine("sqlite://")
    assert captured["postgresql"]["connect_args"] == {"connect_timeout": 2}
    assert captured["postgresql"]["pool_pre_ping"] is True
    assert "connect_args" not in captured["sqlite"]


def test_get_engine_is_cached_and_built_from_settings():
    get_engine.cache_clear()
    try:
        assert get_engine() is get_engine()
        assert get_engine().url.get_backend_name() == "postgresql"
    finally:
        get_engine.cache_clear()


def test_init_db_creates_tables_and_is_idempotent(engine):
    init_db(engine)
    init_db(engine)  # second call must not raise


def test_get_db_yields_a_session_and_closes_it(engine, monkeypatch):
    monkeypatch.setattr(db, "get_engine", lambda: engine)
    gen = get_db()
    session = next(gen)
    assert isinstance(session, Session)
    with pytest.raises(StopIteration):
        next(gen)
    assert not session.in_transaction()


def test_get_db_rolls_back_uncommitted_work_on_error(engine, monkeypatch):
    from datetime import datetime, timezone
    monkeypatch.setattr(db, "get_engine", lambda: engine)
    gen = get_db()
    session = next(gen)
    session.add(Event(source="honeypot", event_type="t", severity="low", description="d",
                      occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    session.flush()
    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("boom"))
    with Session(engine) as fresh:
        assert fresh.scalar(select(func.count()).select_from(Event)) == 0
