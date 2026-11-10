"""The Indicators and Correlation pages, run for real with Streamlit AppTest against a fake API."""
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import FakeBackend, event, indicator

REAL_CLIENT = httpx.Client      # captured once: patching twice in one test must not stack the fakes
HARNESS = str(Path(__file__).with_name("harness.py"))
IP = indicator(1, "ip", "203.0.113.42", sightings=3)
DOM = indicator(2, "domain", "evil.example", sightings=2)
HASH = indicator(3, "sha256", "a" * 64, sightings=1)


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend, page: str) -> AppTest:
    monkeypatch.setenv("TS_PAGE", page)
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()      # the page's cached client must be rebuilt for THIS backend
    return AppTest.from_file(HARNESS, default_timeout=30).run()


def text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def backend() -> FakeBackend:
    events = [event(1, source="honeypot", severity="high", source_ip="203.0.113.42", indicators=[IP, DOM]),
              event(2, source="domain", severity="medium", domain="evil.example", indicators=[DOM]),
              event(3, source="honeypot", severity="critical", risk=95, source_ip="203.0.113.42", indicators=[IP]),
              event(4, source="file", severity="low", file_hash="a" * 64, indicators=[HASH])]
    return FakeBackend(events=events, indicators=[IP, DOM, HASH])


def select(at: AppTest, label: str):
    return next(s for s in at.selectbox if s.label == label)


# ---- indicators ------------------------------------------------------------------------------------

def test_indicators_list_filters_and_caution(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    assert not at.exception
    page = text(at)
    assert "3 match" in page and "203.0.113.42" in page and "evil.example" in page and "SHA-256" in page
    assert "not proof that it is malicious" in page
    at.selectbox(key="ix_type").select("domain").run()
    assert "1 match" in text(at) and "evil.example" in text(at).split("<table")[1]
    at.text_input(key="ix_value").input("nothing-here").run()
    assert "No indicators match" in text(at)


def test_a_partial_ip_filter_shows_a_rejected_filter_state_not_the_unavailable_panel(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    at.selectbox(key="ix_type").select("ip").run()
    at.text_input(key="ix_value").input("203.0.113").run()
    page = text(at)
    assert not at.exception
    assert "Not a valid IP or domain" in page and "did not accept" in page
    assert "Use Refresh" not in page and "Indicators are unavailable" not in page
    assert at.selectbox(key="ix_type").value == "ip" and at.text_input(key="ix_value").value == "203.0.113"


def test_value_label_does_not_promise_normalisation_for_any_type(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    assert at.text_input(key="ix_value").label == "Value (normalised when Type is IP or domain)"


def test_indicator_detail_lists_related_events_from_every_source(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    select(at, "Inspect an indicator").select(2).run()                      # evil.example
    page = text(at)
    assert not at.exception
    for expected in ("Indicator details", "Related events", "2 events from 2 source(s): domain, honeypot", "counted by the backend"):
        assert expected in page, expected


def test_indicator_with_a_hash_finds_its_event(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    select(at, "Inspect an indicator").select(3).run()
    assert "1 events from 1 source(s): file" in text(at)


def test_most_sightings_sort(monkeypatch):
    at = run(monkeypatch, backend(), "indicators")
    at.selectbox(key="ix_sort").select("Most sightings").run()
    table = text(at).split("<tbody>")[1]
    assert table.index("203.0.113.42") < table.index("evil.example") < table.index("a" * 30)       # 3, 2, 1 sightings


def test_indicators_empty_and_down(monkeypatch):
    at = run(monkeypatch, FakeBackend(), "indicators")
    assert not at.exception and "No indicators yet" in text(at)
    at = run(monkeypatch, FakeBackend(indicators=[IP], down=True), "indicators")
    assert not at.exception and "Indicators are unavailable" in text(at) and "203.0.113.42" not in text(at).split("Indicators are unavailable")[1]


# ---- correlation -------------------------------------------------------------------------------------

def test_correlation_summary_table_graph_and_events(monkeypatch):
    at = run(monkeypatch, backend(), "correlation")
    assert not at.exception
    page = text(at)
    for expected in ("Shared indicators", "Cross-source", "Events involved", "cross-source", "Relationship graph", "Events sharing",
                     "not proof that one actor", "not a probability of compromise"):
        assert expected in page, expected
    assert page.count('<div class="ts-kpi-value">') == 3
    assert len(at.get("plotly_chart")) == 1
    assert "203.0.113.42" in page and "evil.example" in page and "a" * 64 not in page.split("Shared indicators")[1].split("Relationship graph")[0]
    codes = [c.value for c in at.code]
    assert len(codes) == 1 and len(codes[0].splitlines()) == 2                # the strongest cluster (domain, cross-source) has 2 events


def test_correlation_filters(monkeypatch):
    at = run(monkeypatch, backend(), "correlation")
    at.checkbox(key="co_cross").check().run()
    shared = text(at).split("Relationship graph")[0]
    assert "evil.example" in shared and "203.0.113.42" not in shared.split("<tbody>")[1].split("</tbody>")[0]
    at.selectbox(key="co_type").select("sha256").run()
    assert "No shared indicators match" in text(at) and len(at.get("plotly_chart")) == 0
    at.checkbox(key="co_cross").uncheck().run()
    at.selectbox(key="co_type").select(None).run()
    at.number_input(key="co_min").set_value(3).run()
    assert "No shared indicators match" in text(at)


def test_correlation_empty_states(monkeypatch):
    assert "No events yet" in text(run(monkeypatch, FakeBackend(), "correlation"))
    lonely = FakeBackend(events=[event(1, indicators=[IP]), event(2, indicators=[DOM])])
    at = run(monkeypatch, lonely, "correlation")
    assert not at.exception and "No shared indicators yet" in text(at) and len(at.get("plotly_chart")) == 0


def test_correlation_backend_down(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, description="MUST NOT APPEAR")], down=True), "correlation")
    assert not at.exception and "Correlation data is unavailable" in text(at) and "MUST NOT APPEAR" not in text(at)


def test_far_dated_indicator_and_event_do_not_break_indicators_or_correlation(monkeypatch):
    far = datetime(9999, 6, 1, tzinfo=timezone.utc)
    ind = indicator(1, "ip", "203.0.113.42", sightings=3, last=far)
    events = [event(1, source="honeypot", source_ip="203.0.113.42", indicators=[ind]),
              event(2, source="domain", at=far, source_ip="203.0.113.42", indicators=[ind])]
    for page in ("indicators", "correlation"):
        at = run(monkeypatch, FakeBackend(events=events, indicators=[ind]), page)
        assert not at.exception, page
        assert "203.0.113.42" in text(at), page
    at = run(monkeypatch, FakeBackend(events=events, indicators=[ind]), "indicators")
    select(at, "Inspect an indicator").select(1).run()
    assert not at.exception


def test_credentials_in_a_url_indicator_are_hidden_in_the_correlation_labels_and_heading(monkeypatch):
    leaky = indicator(9, "url", "http://admin:" + "p" * 60 + "@evil.test/x", sightings=2)      # the cut at 60 falls inside the password
    events = [event(1, indicators=[leaky]), event(2, indicators=[leaky])]
    at = run(monkeypatch, FakeBackend(events=events, indicators=[leaky]), "correlation")
    assert not at.exception
    shown = text(at) + "\n".join(o for s in at.selectbox for o in s.options)
    assert "Events sharing" in shown and "[redacted]" in shown
    assert "admin:" not in shown and "ppppp" not in shown
