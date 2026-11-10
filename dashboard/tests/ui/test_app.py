"""Run the real Streamlit app (app.py) headlessly against a fake backend, via Streamlit's AppTest."""
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import FakeBackend, HEALTH_DOWN, T0, event, incident, indicator

REAL_CLIENT = httpx.Client
APP = str(Path(__file__).resolve().parents[2] / "app.py")


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    """No real network, no .env, and no client cached from another test."""
    monkeypatch.delenv("THREATSCOPE_API_URL", raising=False)
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend, page: str | None = None) -> AppTest:
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()      # the page's cached client must be rebuilt for THIS backend
    at = AppTest.from_file(APP, default_timeout=30)
    if page:
        at.query_params["page"] = page
    return at.run()


def html(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def test_overview_shows_real_numbers_and_healthy_status(monkeypatch):
    events = [event(1, severity="critical", risk=90, source_ip="203.0.113.9"), event(2, severity="high"),
              event(3, severity="high", source="domain", domain="evil.example")]
    backend = FakeBackend(events=events, indicators=[indicator(1, sightings=3)], incidents=[incident(1, "open")])
    at = run(monkeypatch, backend)
    assert not at.exception
    text = html(at)
    assert "API healthy" in text and "Database healthy" in text
    for expected in ("Total events", "Critical events", "High severity events", "Total indicators", "Open incidents",
                     "Events over time", "Events by severity", "Events by source", "Recent security events",
                     "Top recurring indicators", "Recent high-risk activity", "not a probability of compromise"):
        assert expected in text, expected
    assert '<div class="ts-kpi-value">3</div>' in text            # total events
    assert len(at.get("plotly_chart")) == 3
    assert {r.method for r in backend.requests} == {"GET"}


def test_kpi_is_named_high_severity(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, severity="critical"), event(2, severity="high")]))
    text = html(at)
    assert "High severity events" in text and "High-risk events" not in text
    assert "Recent high-risk activity" in text                  # that panel does include critical, so it keeps its name


def test_empty_database_shows_intentional_empty_states_and_no_charts(monkeypatch):
    at = run(monkeypatch, FakeBackend())
    assert not at.exception
    text = html(at)
    assert "No events yet" in text and "No events to plot" in text and "Nothing recurring yet" in text and "No high-risk events" in text
    assert len(at.get("plotly_chart")) == 0
    assert '<div class="ts-kpi-value">0</div>' in text


def test_backend_down_shows_error_not_data_and_does_not_crash(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, description="MUST NOT APPEAR")], down=True))
    assert not at.exception
    text = html(at)
    assert "API unavailable" in text and "Database unknown" in text and "Overview data is unavailable" in text
    assert "Cannot reach the ThreatScope API" in text and "MUST NOT APPEAR" not in text
    assert len(at.get("plotly_chart")) == 0


def test_database_down_is_reported_separately(monkeypatch):
    at = run(monkeypatch, FakeBackend(health=HEALTH_DOWN, health_status=503))
    assert not at.exception and "API healthy" in html(at) and "Database unavailable" in html(at)


def test_hostile_event_text_is_not_rendered_as_html(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, description='<img src=x onerror=alert(1)>', event_type="x<script>")]))
    text = html(at)
    assert "<img src=x" not in text and "<script>" not in text and "&lt;img src=x" in text


def test_invalid_configuration_is_a_message_not_a_traceback(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://user:secret@host")
    at = run(monkeypatch, FakeBackend())
    assert not at.exception
    text = html(at)
    assert "Dashboard configuration is invalid" in text and "secret" not in text


def test_no_secret_or_api_key_in_the_rendered_page(monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", "0123456789abcdefSECRETKEY")
    at = run(monkeypatch, FakeBackend(events=[event(1)]))
    assert "SECRETKEY" not in html(at) and "SECRETKEY" not in repr(at)


def test_overview_with_only_far_dated_events_says_why_the_chart_is_empty(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, at=datetime(1900, 1, 1, tzinfo=timezone.utc))]))
    chart = html(at).split("Events over time")[1].split("Events by severity")[0]
    assert not at.exception
    assert "No event times within the last ~10 years to plot" in chart and "Run an adapter" not in chart
    assert "No events to plot" not in html(at)


def test_overview_with_no_events_keeps_the_adapter_hint_in_the_chart(monkeypatch):
    at = run(monkeypatch, FakeBackend())
    chart = html(at).split("Events over time")[1].split("Events by severity")[0]
    assert "No events to plot" in chart and "Run an adapter" in chart


def test_overview_with_far_dated_events_renders_and_says_they_are_left_out_of_the_chart(monkeypatch):
    far = [event(2, at=datetime(9999, 6, 1, tzinfo=timezone.utc)), event(3, at=datetime(1900, 1, 1, tzinfo=timezone.utc))]
    at = run(monkeypatch, FakeBackend(events=[event(1), *far]))
    assert not at.exception
    assert "outside the chart range" in html(at)
    assert len(at.get("plotly_chart")) == 3
