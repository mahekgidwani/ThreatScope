from datetime import timedelta

import pytest

from tests.conftest import make_api
from tests.fake_backend import FakeBackend, T0, incident
from ts_dashboard import components as c
from ts_dashboard import incidents as ic
from ts_dashboard.models import Incident

A = "7c27133f-9c0d-4878-a800-5b2278eca1f5"
B = "00000000-0000-4000-8000-000000000002"


def api_for(backend):
    return make_api(backend)[0]


def many(n=12):
    return FakeBackend(incidents=[{**incident(i, "open" if i % 3 else "closed"), "created_at": (T0 + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")}
                                  for i in range(1, n + 1)])


def test_status_counts_are_exact_per_status_and_overall():
    backend = FakeBackend(incidents=[incident(1, "open"), incident(2, "open"), incident(3, "investigating"), incident(4, "closed")])
    assert ic.status_counts(api_for(backend)) == {"open": 2, "investigating": 1, "closed": 1, "all": 4}
    assert ic.status_counts(api_for(FakeBackend())) == {"open": 0, "investigating": 0, "closed": 0, "all": 0}


def test_pages_filter_clamp_and_do_not_overlap():
    api = api_for(many())
    first, second = (ic.fetch_incident_page(api, None, p, 5) for p in (0, 1))
    assert first.total == 12 and first.pages == 3 and (first.first_item, first.last_item) == (1, 5)
    assert not {i.id for i in first.items} & {i.id for i in second.items}
    assert [i.id for i in first.items] == [12, 11, 10, 9, 8]                       # newest first
    assert ic.fetch_incident_page(api, None, 99, 5).page == 2 and ic.fetch_incident_page(api, None, -4, 5).page == 0
    closed = ic.fetch_incident_page(api, "closed", 0, 50)
    assert closed.total == 4 and {i.status for i in closed.items} == {"closed"}


def test_empty_page():
    page = ic.fetch_incident_page(api_for(FakeBackend()), None, 3, 10)
    assert (page.items, page.total, page.page, page.pages, page.first_item) == ([], 0, 0, 1, 0)


@pytest.mark.parametrize("text, valid, invalid", [
    ("", [], []), ("   \n ", [], []),
    (A, [A], []), (f"{A}\n{B}", [A, B], []), (f"{A}, {B};{A.upper()}", [A, B], []),            # separators, case, duplicates
    (f"{A} nonsense", [A], ["nonsense"]), ("12345", [], ["12345"]),
    ("x" * 100, [], ["x" * 40]),                                                               # long junk is cut for display
])
def test_event_ids_are_read_from_pasted_text(text, valid, invalid):
    assert ic.parse_event_ids(text) == (valid, invalid)


def test_default_title_names_the_indicator_and_is_bounded():
    assert ic.default_title("ip", "203.0.113.42") == "Events sharing IP address 203.0.113.42"
    assert ic.default_title("sha256", "a" * 64).endswith("…") and len(ic.default_title("domain", "x" * 200)) < 100


# ---- html -----------------------------------------------------------------------------------------------

def raw_incident(**over) -> Incident:
    return Incident.model_validate({k: v for k, v in {**incident(7), **over, "event_count": over.get("event_count", 3)}.items() if k != "event_ids"})


def test_status_badges_have_text_and_unknown_status_is_safe():
    assert "Investigating" in c.status_badge("investigating") and "st-investigating" in c.status_badge("investigating")
    assert "st-closed" in c.status_badge("<x>") and "<x>" not in c.status_badge("<x>")


def test_incident_tables_escape_and_show_counts():
    hostile = raw_incident(title="<script>x</script>", summary="<img src=x onerror=1>")
    html = c.incidents_table([hostile]) + c.incident_detail(hostile)
    assert "<script>" not in html and "<img" not in html and "&lt;script&gt;" in html and "&lt;img" in html
    assert "#7" in html and "Updated (UTC)" in html and "highest of its events" in html


def test_incident_detail_without_notes():
    assert "none yet" in c.incident_detail(raw_incident())
