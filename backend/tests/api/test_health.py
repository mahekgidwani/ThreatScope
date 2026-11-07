"""GET /health: API and database are reported separately, plus an overall readiness status."""
import logging
import time

import pytest

from app.api.deps import get_engine_dep
from app.db import make_engine

SECRET_PASSWORD = "pw-FAKE-health-123"
DEAD_DATABASE = f"postgresql+psycopg://health_user:{SECRET_PASSWORD}@127.0.0.1:1/health_db"   # port 1: refused


@pytest.fixture
def dead_database(client):
    """Make the health check see a database that cannot be reached."""
    engine = make_engine(DEAD_DATABASE)
    client.app.dependency_overrides[get_engine_dep] = lambda: engine
    yield engine
    engine.dispose()


def test_ready_when_the_database_answers(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["api"] == {"status": "up"}
    assert data["database"]["status"] == "up"
    assert isinstance(data["database"]["latency_ms"], float) and data["database"]["latency_ms"] >= 0


def test_response_has_exactly_the_documented_shape(client):
    data = client.get("/health").json()
    assert set(data) == {"status", "api", "database"}
    assert set(data["api"]) == {"status"}
    assert set(data["database"]) == {"status", "latency_ms"}


def test_database_down_is_reported_separately_with_503(client, dead_database):
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "api": {"status": "up"},
                               "database": {"status": "down", "latency_ms": None}}


def test_database_down_response_leaks_nothing(client, dead_database):
    text = client.get("/health").text
    for leaked in ("psycopg", "127.0.0.1", "health_user", "health_db", SECRET_PASSWORD, "password",
                   "Traceback", "OperationalError", "refused"):
        assert leaked not in text, leaked


def test_database_down_is_logged_without_credentials(client, dead_database, caplog):
    with caplog.at_level(logging.DEBUG):
        client.get("/health")
    assert SECRET_PASSWORD not in caplog.text
    assert any(r.levelno == logging.WARNING and "database check failed" in r.getMessage() for r in caplog.records)


def test_database_down_answers_quickly(client, dead_database):
    started = time.perf_counter()
    client.get("/health")
    assert time.perf_counter() - started < 5


def test_health_needs_no_api_key_and_is_never_cached(client):
    response = client.get("/health")                      # no X-API-Key header
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


def test_503_is_not_cached_either(client, dead_database):
    assert client.get("/health").headers["cache-control"] == "no-store"


def test_health_is_documented_in_openapi(client):
    assert "/health" in client.get("/openapi.json").json()["paths"]
