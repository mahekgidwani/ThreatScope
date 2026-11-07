"""The Events page, run for real with Streamlit AppTest against a fake API."""
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import FakeBackend, T0, event, indicator

REAL_CLIENT = httpx.Client      # captured once: patching twice in one test must not stack the fakes
HARNESS = str(Path(__file__).with_name("harness.py"))
ID_1 = "00000000-0000-4000-8000-000000000001"


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("TS_PAGE", "events")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend) -> AppTest:
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()      # the page's cached client must be rebuilt for THIS backend
    return AppTest.from_file(HARNESS, default_timeout=30).run()


def text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def rows(at: AppTest) -> int:
    return text(at).count('<span class="ts-mono">xss_attempt</span>')


def table_html(at: AppTest) -> str:
    return text(at).split("<table", 1)[1].split("</table>", 1)[0]


def pick(at: AppTest, event_id: str) -> AppTest:
    return next(s for s in at.selectbox if s.label == "Inspect an event").select(event_id).run()


def backend_with_events(n=30):
    return FakeBackend(events=[event(i, source_ip="203.0.113.42" if i % 2 else None, severity="critical" if i % 5 == 0 else "high")
                               for i in range(1, n + 1)])


def test_page_shows_filters_grid_and_pager(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    assert not at.exception
    assert "30 match" in text(at) and "newest first" in text(at)
    assert "Showing 1–25 of 30" in text(at) and "page 1 of 2" in text(at)
    assert rows(at) == 25
    labels = {s.label for s in at.selectbox} | {t.label for t in at.text_input}
    assert {"Search", "Source", "Severity", "Event type", "Time range (UTC)", "Sort by occurrence time", "Rows per page"} <= labels
    assert "Inspect an event" in {s.label for s in at.selectbox} and "not a probability of compromise" in text(at)


def test_next_and_previous_page(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    assert at.button(key="ev_prev").disabled is True
    at.button(key="ev_next").click().run()
    assert "Showing 26–30 of 30" in text(at) and "page 2 of 2" in text(at) and rows(at) == 5
    assert at.button(key="ev_next").disabled is True
    at.button(key="ev_prev").click().run()
    assert "Showing 1–25" in text(at)


def test_filtering_resets_to_page_one_and_narrows(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    at.button(key="ev_next").click().run()
    at.selectbox(key="ev_severity").select("critical").run()
    assert "6 match" in text(at) and "Showing 1–6 of 6" in text(at) and rows(at) == 6
    assert "Critical" in table_html(at) and ">High<" not in table_html(at)


def test_oldest_first(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    assert "07 Nov 2026 04:30 UTC" in table_html(at).split("<tbody>")[1].split("</tr>")[0]       # newest first by default
    at.selectbox(key="ev_sort").select("Oldest first").run()
    first_row = table_html(at).split("<tbody>")[1].split("</tr>")[0]
    assert "oldest first" in text(at) and "07 Nov 2026 04:01 UTC" in first_row


def test_search_by_ip_filters_and_search_by_unsupported_text_explains(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    at.text_input(key="ev_search").input("203.0.113.42").run()
    assert "15 match" in text(at)
    at.text_input(key="ev_search").input("a" * 64).run()
    assert "That search cannot be run" in text(at) and "cannot filter events by file hash" in text(at)
    assert rows(at) == 0


def test_search_by_event_id_shows_the_detail_with_hidden_secrets_and_related_events(monkeypatch):
    backend = FakeBackend(events=[
        event(1, source_ip="203.0.113.42", description="<img src=x onerror=alert(1)>",
              metadata={"rule": "9500001", "api_key": "SUPERSECRET123", "nested": {"password": "hunter2"}},
              indicators=[indicator(value="203.0.113.42", sightings=2)]),
        event(2, source_ip="203.0.113.42")])
    at = run(monkeypatch, backend)
    at = pick(run(monkeypatch, backend), ID_1)
    assert not at.exception
    page = text(at)
    for expected in ("Event details", "Risk score", "Experimental prioritisation score", "severity:high", "Indicators in this event",
                     "Metadata", "Related events", "Also seen with source IP 203.0.113.42"):
        assert expected in page, expected
    assert "<img src=x" not in page and "&lt;img src=x" in page
    shown = repr([j.value for j in at.json])
    assert "9500001" in shown and "SUPERSECRET123" not in shown and "hunter2" not in shown and "[redacted]" in shown
    assert "SUPERSECRET123" not in page


def test_unknown_event_id_is_a_friendly_error(monkeypatch):
    at = run(monkeypatch, backend_with_events(2))
    at.text_input(key="ev_search").input("11111111-1111-4111-8111-111111111111").run()
    assert not at.exception and "Event could not be loaded" in text(at) and "That record was not found" in text(at)


def test_empty_database_and_empty_filter_result(monkeypatch):
    at = run(monkeypatch, FakeBackend())
    assert not at.exception and "No events yet" in text(at) and rows(at) == 0
    at = run(monkeypatch, backend_with_events(3))
    at.selectbox(key="ev_source").select("file").run()
    assert "No events match" in text(at) and "Change or clear the filters" in text(at)


def test_clear_filters_restores_everything(monkeypatch):
    at = run(monkeypatch, backend_with_events())
    at.selectbox(key="ev_severity").select("critical").run()
    assert "6 match" in text(at)
    next(b for b in at.button if b.label == "Clear filters").click().run()
    assert "30 match" in text(at)


def test_custom_range_with_reversed_dates_is_reported(monkeypatch):
    from datetime import date
    at = run(monkeypatch, backend_with_events(3))
    at.selectbox(key="ev_range").select("Custom (UTC dates)").run()
    at.date_input(key="ev_from").set_value(date(2026, 11, 9)).run()
    at.date_input(key="ev_to").set_value(date(2026, 11, 1)).run()
    assert "From date is after the To date" in text(at)


def test_backend_down_shows_error_not_events(monkeypatch):
    at = run(monkeypatch, FakeBackend(events=[event(1, description="MUST NOT APPEAR")], down=True))
    assert not at.exception and "Events are unavailable" in text(at) and rows(at) == 0
    assert "MUST NOT APPEAR" not in text(at)
