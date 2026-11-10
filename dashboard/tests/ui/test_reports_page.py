"""The Reports page, run for real with Streamlit AppTest against the fake API."""
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import FakeBackend, event, incident, indicator, tick_clock

REAL_CLIENT = httpx.Client
HARNESS = str(Path(__file__).with_name("harness.py"))
IP = indicator(1, "ip", "203.0.113.42", sightings=3)


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("TS_PAGE", "reports")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend) -> AppTest:
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()
    return AppTest.from_file(HARNESS, default_timeout=60).run()


def text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def backend() -> FakeBackend:
    events = [event(1, severity="critical", risk=90, source_ip="203.0.113.42", indicators=[IP], event_type="sqli_attempt"),
              event(2, severity="high", risk=60, source_ip="203.0.113.42", indicators=[IP]),
              event(3, severity="low", risk=20, source="file", event_type="file_analysis", description="=HYPERLINK(\"http://evil\")")]
    return FakeBackend(events=events, indicators=[IP], incidents=[incident(1, "open", "critical", (events[0]["id"], events[1]["id"]), title="Probes")])


def button(at: AppTest, label_start: str):
    return next(b for b in at.button if b.label.startswith(label_start))


def test_report_sections_numbers_and_labels(monkeypatch):
    at = run(monkeypatch, backend())
    assert not at.exception
    page = text(at)
    for expected in ("Events in scope", "Critical or high", "Sources reporting", "Recurring indicators", "Severity distribution", "Events by source",
                     "Most frequent event types", "High-risk events", "Top recurring indicators", "not a probability of compromise", "Export",
                     "sqli_attempt", "203.0.113.42", "not proof of malicious activity"):
        assert expected in page, expected
    assert '<div class="ts-kpi-value">3</div>' in page and '<div class="ts-kpi-value">2</div>' in page
    assert len(at.get("plotly_chart")) == 2
    labels = [d.label for d in at.get("download_button")]
    assert "Download summary report (Markdown)" in labels and "Download incident summary (Markdown)" in labels


def test_high_risk_subtitle_names_the_sample_only_when_sampled(monkeypatch):
    assert "newest 200 per severity" not in text(run(monkeypatch, backend()))
    big = FakeBackend(events=[event(n, severity="high") for n in range(1, 202)])
    assert "from the newest 200 per severity" in text(run(monkeypatch, big))


def test_filters_change_the_report(monkeypatch):
    at = run(monkeypatch, backend())
    at.selectbox(key="rp_source").select("file").run()
    page = text(at)
    assert not at.exception and '<div class="ts-kpi-value">1</div>' in page and "No high-risk events" in page and "Nothing recurring" in page
    at.selectbox(key="rp_severity").select("critical").run()
    assert "No events in this scope" in text(at) and len(at.get("plotly_chart")) == 0


def test_csv_is_prepared_on_demand_and_resets_when_the_scope_changes(monkeypatch):
    b = backend()
    at = run(monkeypatch, b)
    assert "Download events CSV" not in [d.label for d in at.get("download_button")]
    assert not [r for r in b.requests if r.url.params.get("limit") == "100" and r.url.params.get("offset") == "100"]
    button(at, "Prepare events CSV").click().run()
    assert not at.exception and "Ready: 3 of 3 events in scope" in text(at) and "neutralised" in text(at)
    assert "Download events CSV" in [d.label for d in at.get("download_button")]
    at.selectbox(key="rp_source").select("file").run()
    assert "Download events CSV" not in [d.label for d in at.get("download_button")] and "Prepare it again" in text(at)


def test_csv_download_stays_available_after_prepare(monkeypatch):
    import views.reports
    tick_clock(monkeypatch, views.reports)
    at = run(monkeypatch, backend())
    at.selectbox(key="rp_range").select("Last 24 hours").run()
    button(at, "Prepare events CSV").click().run()
    assert "Ready: 3 of 3 events in scope" in text(at)
    at.run()                                                # a plain rerun: the relative range must not drift
    assert "filters changed" not in text(at)
    assert "Download events CSV" in [d.label for d in at.get("download_button")]


def test_custom_range_with_reversed_dates(monkeypatch):
    from datetime import date
    at = run(monkeypatch, backend())
    at.selectbox(key="rp_range").select("Custom (UTC dates)").run()
    at.date_input(key="rp_from").set_value(date(2026, 11, 9)).run()
    at.date_input(key="rp_to").set_value(date(2026, 11, 1)).run()
    assert "That range cannot be reported" in text(at) and "From date is after the To date" in text(at)


def test_empty_database(monkeypatch):
    at = run(monkeypatch, FakeBackend())
    assert not at.exception and "No events in this scope" in text(at) and len(at.get("plotly_chart")) == 0


def test_no_incidents_means_no_incident_download(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1)]))
    assert "no investigation summary to download" in text(at)
    assert "Download incident summary (Markdown)" not in [d.label for d in at.get("download_button")]


def test_backend_down(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, description="MUST NOT APPEAR")], down=True))
    assert not at.exception and "The report is unavailable" in text(at) and "MUST NOT APPEAR" not in text(at)


def test_credentials_in_an_incident_title_are_hidden_in_the_summary_picker(monkeypatch):
    title = "look at http://admin:" + "p" * 70 + "@evil.test/x"      # the cut at 70 falls inside the password
    events = [event(1, severity="critical")]
    at = run(monkeypatch, FakeBackend(events=events, incidents=[incident(1, "open", "critical", (events[0]["id"],), title=title)]))
    assert not at.exception
    options = "\n".join(o for s in at.selectbox if s.label == "Investigation summary for an incident" for o in s.options)
    assert "[redacted]" in options and "admin:" not in options and "ppppp" not in options
