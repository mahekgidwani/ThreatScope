"""The Status page, run for real with Streamlit AppTest against a fake API (it was only covered by tests/live)."""
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import HEALTH_DOWN, FakeBackend

REAL_CLIENT = httpx.Client      # captured once: patching twice in one test must not stack the fakes
HARNESS = str(Path(__file__).with_name("harness.py"))


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("TS_PAGE", "status")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend) -> AppTest:
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()      # the page's cached client must be rebuilt for THIS backend
    return AppTest.from_file(HARNESS, default_timeout=30).run()


def text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def test_status_page_renders_ready_and_database_down_and_api_down(monkeypatch):
    at = run(monkeypatch, FakeBackend())
    assert not at.exception
    page = text(at)
    assert "System status" in page and "query latency 3.8 ms" in page and "ready = the API can serve requests" in page
    assert "Unavailable" not in page and "ThreatScope API is unavailable" not in page

    at = run(monkeypatch, FakeBackend(health=HEALTH_DOWN, health_status=503))
    assert not at.exception
    page = text(at)
    assert "the API cannot reach the database" in page and "Unavailable" in page and "not ready" in page
    assert "query latency" not in page and "ThreatScope API is unavailable" not in page

    at = run(monkeypatch, FakeBackend(down=True))
    assert not at.exception
    page = text(at)
    assert "ThreatScope API is unavailable" in page and "docker compose up -d" in page
    assert "query latency" not in page and "ready = the API can serve requests" not in page
