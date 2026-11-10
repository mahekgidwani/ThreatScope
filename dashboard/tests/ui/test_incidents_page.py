"""The Incidents page, run for real with Streamlit AppTest against the fake API (which enforces the key like the real one)."""
from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.fake_backend import FakeBackend, TEST_KEY, event, incident, indicator

REAL_CLIENT = httpx.Client
HARNESS = str(Path(__file__).with_name("harness.py"))
IP = indicator(1, "ip", "203.0.113.42", sightings=3)
E1, E2, E3 = (f"00000000-0000-4000-8000-{n:012d}" for n in (1, 2, 3))


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("TS_PAGE", "incidents")
    monkeypatch.setenv("INGEST_API_KEY", TEST_KEY)
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def run(monkeypatch, backend: FakeBackend, key: str | None = TEST_KEY) -> AppTest:
    if key is None:
        monkeypatch.delenv("INGEST_API_KEY", raising=False)
        monkeypatch.setenv("INGEST_API_KEY", "")
    else:
        monkeypatch.setenv("INGEST_API_KEY", key)
    monkeypatch.setattr(httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(backend), **kw))
    st.cache_resource.clear()
    return AppTest.from_file(HARNESS, default_timeout=30).run()


def text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def backend(**over) -> FakeBackend:
    events = [event(1, severity="high", risk=60, source_ip="203.0.113.42", indicators=[IP]),
              event(2, severity="critical", risk=95, source_ip="203.0.113.42", indicators=[IP]),
              event(3, severity="low", risk=20, source="file")]
    return FakeBackend(events=events, indicators=[IP],
                       incidents=over.pop("incidents", [incident(1, "open", "high", (E1, E2), title="Probes from one IP", summary="first note")]), **over)


def button(at: AppTest, label: str):
    return next(b for b in at.button if b.label == label)


def writes(b: FakeBackend):
    return [r for r in b.requests if r.method != "GET"]


def box(at: AppTest, label: str):
    """A create-form widget by its label (its key changes after every create, so the key is not a stable handle).
    The create panel is the last on the page, after the editor of a focused incident, which has a "Title" too."""
    return [w for w in [*at.text_input, *at.text_area] if w.label == label][-1]


# ---- reading ---------------------------------------------------------------------------------------------

def test_summary_cards_list_and_detail(monkeypatch):
    b = backend(incidents=[incident(1, "open", "high", (E1, E2)), incident(2, "investigating", "low", (E3,)), incident(3, "closed", "high", (E1,))])
    at = run(monkeypatch, b)
    assert not at.exception
    page = text(at)
    for expected in ("Open", "Investigating", "Closed", "All incidents", "3 match", "Incident 1", "Incident 2", "Create an incident"):
        assert expected in page, expected
    assert page.count('<div class="ts-kpi-value') == 4
    at.selectbox(key="ic_pick").select(2).run()
    page = text(at)
    assert not at.exception and "Incident #2" in page and "Events in this incident" in page and "not a probability of compromise" in page
    assert "file" in page.lower()
    assert [c.value for c in at.code] and E3 in at.code[0].value


def test_filter_by_status(monkeypatch):
    at = run(monkeypatch, backend(incidents=[incident(1, "open", event_ids=(E1,)), incident(2, "closed", event_ids=(E2,))]))
    at.selectbox(key="ic_status").select("closed").run()
    assert "1 match" in text(at) and "Incident 2" in text(at).split("<tbody>")[1].split("</tbody>")[0]


def test_empty_state_explains_what_an_incident_is(monkeypatch):
    at = run(monkeypatch, backend(incidents=[]))
    assert not at.exception and "No incidents yet" in text(at) and "not a confirmed attack" in text(at)


def test_backend_down(monkeypatch):
    at = run(monkeypatch, backend(down=True))
    assert not at.exception and "Incidents are unavailable" in text(at) and "Create an incident" not in text(at)


# ---- no key: read-only -------------------------------------------------------------------------------------

def test_without_a_key_the_page_is_read_only_and_sends_no_writes(monkeypatch):
    b = backend()
    at = run(monkeypatch, b, key=None)
    at.selectbox(key="ic_pick").select(1).run()
    page = text(at)
    assert not at.exception and "Read-only" in page and "INGEST_API_KEY" in page
    assert len(at.text_area) == 0 and not [x for x in at.button if x.label in ("Save changes", "Create incident")]
    assert writes(b) == []


# ---- writing --------------------------------------------------------------------------------------------------

def test_status_title_and_notes_are_saved(monkeypatch):
    b = backend()
    at = run(monkeypatch, b)
    at.selectbox(key="ic_pick").select(1).run()
    form = [s for s in at.selectbox if s.label == "Status"][-1]          # the first "Status" is the list filter
    form.select("investigating")
    next(t for t in at.text_input if t.label == "Title").set_value("Same IP, three probes")
    next(t for t in at.text_area if t.label == "Investigation notes").set_value("Checked the honeypot log; same user agent.")
    button(at, "Save changes").click().run()
    assert not at.exception
    assert b.incidents[0]["status"] == "investigating" and b.incidents[0]["title"] == "Same IP, three probes"
    assert b.incidents[0]["summary"] == "Checked the honeypot log; same user agent."
    assert "Investigating" in text(at) and "Same IP, three probes" in text(at)
    assert [t.value for t in at.toast] == ["Incident updated"]
    patch = writes(b)[0]
    assert patch.method == "PATCH" and patch.headers["x-api-key"] == TEST_KEY


def test_clearing_the_notes_clears_them(monkeypatch):
    b = backend()
    at = run(monkeypatch, b)
    at.selectbox(key="ic_pick").select(1).run()
    next(t for t in at.text_area if t.label == "Investigation notes").set_value("   ")
    button(at, "Save changes").click().run()
    assert b.incidents[0]["summary"] is None


def test_events_can_be_added_by_id_and_removed(monkeypatch):
    b = backend()
    at = run(monkeypatch, b)
    at.selectbox(key="ic_pick").select(1).run()
    next(t for t in at.text_area if t.label == "Add events by ID").set_value(f"{E3}\n")
    button(at, "Update events").click().run()
    assert b.incidents[0]["event_ids"] == [E1, E2, E3] and b.incidents[0]["severity"] == "critical"
    at.multiselect[0].set_value([E2, E3]).run()
    button(at, "Update events").click().run()
    assert b.incidents[0]["event_ids"] == [E1] and b.incidents[0]["severity"] == "high" and b.incidents[0]["risk_score"] == 60


def test_bad_ids_and_empty_member_changes_are_explained_and_not_sent(monkeypatch):
    b = backend()
    at = run(monkeypatch, b)
    at.selectbox(key="ic_pick").select(1).run()
    next(t for t in at.text_area if t.label == "Add events by ID").set_value("not-an-id")
    button(at, "Update events").click().run()
    assert "Some IDs are not event IDs" in text(at) and writes(b) == []
    next(t for t in at.text_area if t.label == "Add events by ID").set_value("")
    button(at, "Update events").click().run()
    assert "Nothing to change" in text(at) and writes(b) == []


def test_removing_every_event_is_refused_by_the_api_and_shown(monkeypatch):
    b = backend(incidents=[incident(1, "open", "high", (E1,))])
    at = run(monkeypatch, b)
    at.selectbox(key="ic_pick").select(1).run()
    at.multiselect[0].set_value([E1]).run()
    button(at, "Update events").click().run()
    assert not at.exception and "Events were not updated" in text(at)
    assert "an incident must keep at least one event" in text(at)
    assert b.incidents[0]["event_ids"] == [E1]


def test_a_wrong_key_is_reported_with_guidance(monkeypatch):
    at = run(monkeypatch, backend(api_key="a-different-key-entirely"))
    at.selectbox(key="ic_pick").select(1).run()
    button(at, "Save changes").click().run()
    assert "Changes were not saved" in text(at) and "Check INGEST_API_KEY" in text(at) and TEST_KEY not in text(at)


# ---- creating --------------------------------------------------------------------------------------------------

def test_create_from_a_shared_indicator_groups_exactly_its_events(monkeypatch):
    b = backend(incidents=[])
    at = run(monkeypatch, b)
    assert "Events sharing IP address 203.0.113.42" in "".join(t.value for t in at.text_input)
    assert "2 events will be grouped" in text(at)
    button(at, "Create incident").click().run()
    assert not at.exception
    assert len(b.incidents) == 1 and set(b.incidents[0]["event_ids"]) == {E1, E2}
    assert b.incidents[0]["title"] == "Events sharing IP address 203.0.113.42" and b.incidents[0]["severity"] == "critical"
    assert "Incident #1" in text(at) and [t.value for t in at.toast] == ["Incident #1 created"]
    assert writes(b)[0].headers["x-api-key"] == TEST_KEY


def test_create_from_ids_validates_before_enabling_the_button(monkeypatch):
    b = backend(incidents=[])
    at = run(monkeypatch, b)
    at.radio(key="ic_mode").set_value("From event IDs").run()
    assert button(at, "Create incident").disabled
    box(at, "Event IDs").set_value(f"{E3} garbage").run()
    assert "Some IDs are not event IDs" in text(at)
    box(at, "Event IDs").set_value(E3).run()
    next(t for t in at.text_input if t.label == "Title").set_value("Dropped file").run()
    assert not button(at, "Create incident").disabled
    button(at, "Create incident").click().run()
    assert b.incidents[0]["event_ids"] == [E3] and b.incidents[0]["title"] == "Dropped file" and b.incidents[0]["severity"] == "low"


def test_create_form_is_cleared_after_a_successful_create(monkeypatch):
    b = backend(incidents=[])
    at = run(monkeypatch, b)
    at.radio(key="ic_mode").set_value("From event IDs").run()
    box(at, "Event IDs").set_value(E3).run()
    box(at, "Title").set_value("Dropped file").run()
    box(at, "Notes (optional)").set_value("seen once").run()
    button(at, "Create incident").click().run()
    assert len(b.incidents) == 1
    assert box(at, "Event IDs").value == "" and box(at, "Title").value == "" and box(at, "Notes (optional)").value == ""
    assert button(at, "Create incident").disabled
    at.run()                                                  # a rerun must not repeat the create either
    assert len(b.incidents) == 1 and len(writes(b)) == 1


def test_a_second_create_from_the_same_shared_indicator_is_not_offered(monkeypatch):
    b = backend(incidents=[])
    at = run(monkeypatch, b)
    button(at, "Create incident").click().run()
    assert len(b.incidents) == 1
    assert button(at, "Create incident").disabled and box(at, "Notes (optional)").value == ""
    assert len(writes(b)) == 1


def test_creating_with_an_unknown_event_shows_the_api_error(monkeypatch):
    b = backend(incidents=[])
    at = run(monkeypatch, b)
    at.radio(key="ic_mode").set_value("From event IDs").run()
    box(at, "Event IDs").set_value("11111111-1111-4111-8111-111111111111").run()
    next(t for t in at.text_input if t.label == "Title").set_value("Ghost").run()
    button(at, "Create incident").click().run()
    assert "The incident was not created" in text(at) and "That record was not found" in text(at) and b.incidents == []


def test_no_shared_indicators_offers_the_id_route(monkeypatch):
    b = FakeBackend(events=[event(1, indicators=[IP])])
    at = run(monkeypatch, b)
    assert "No shared indicators yet" in text(at) and "group events by ID" in text(at)
