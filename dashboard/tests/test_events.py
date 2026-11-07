from datetime import date, datetime, timedelta, timezone

import pytest

from tests.conftest import make_api
from tests.fake_backend import FakeBackend, T0, event
from ts_dashboard import components as c
from ts_dashboard import events as ev
from ts_dashboard.models import Event

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
UUID_TEXT = "7c27133f-9c0d-4878-a800-5b2278eca1f5"


def api_for(backend):
    return make_api(backend)[0]


def ids(page: ev.EventPage) -> list[str]:
    return [e.external_event_id for e in page.items]


# ---- the search box ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, kind, value", [
    ("", "empty", ""), ("   ", "empty", ""),
    (UUID_TEXT, "event_id", UUID_TEXT), (UUID_TEXT.upper(), "event_id", UUID_TEXT), (f"  {UUID_TEXT} ", "event_id", UUID_TEXT),
    ("203.0.113.42", "ip", "203.0.113.42"), ("2001:0DB8::0001", "ip", "2001:db8::1"),
    ("Evil.Example", "domain", "evil.example"), ("xn--pypal-4ve.com", "domain", "xn--pypal-4ve.com"),
])
def test_search_text_is_classified(text, kind, value):
    query = ev.classify_search(text)
    assert (query.kind, query.value) == (kind, value)


@pytest.mark.parametrize("text", ["a" * 64, "http://evil.example/x", "two words", "a/b", "x@y", "d" * 300])
def test_search_text_the_api_cannot_filter_is_refused_with_a_reason(text):
    query = ev.classify_search(text)
    assert query.kind == "unsupported" and query.message


def test_hash_and_url_searches_say_what_is_missing():
    assert "file hash or URL" in ev.classify_search("a" * 64).message


# ---- filters and time ranges --------------------------------------------------------------------

def test_filters_only_send_what_is_set():
    assert ev.EventFilters().params() == {} and not ev.EventFilters().active
    f = ev.EventFilters(source="file", severity="low")
    assert f.params() == {"source": "file", "severity": "low"} and f.active


def test_time_range_presets_and_all_time():
    assert ev.time_range("All time", NOW) == (None, None)
    assert ev.time_range("Last 24 hours", NOW) == (NOW - timedelta(hours=24), None)
    assert ev.time_range("Last hour", NOW)[0] == NOW - timedelta(hours=1)


def test_custom_range_is_whole_utc_days_with_the_end_date_included():
    start, end = ev.time_range(ev.CUSTOM_RANGE, NOW, date(2026, 11, 1), date(2026, 11, 3))
    assert start == datetime(2026, 11, 1, tzinfo=timezone.utc) and end == datetime(2026, 11, 4, tzinfo=timezone.utc)
    assert ev.time_range(ev.CUSTOM_RANGE, NOW, None, None) == (None, None)
    assert ev.time_range(ev.CUSTOM_RANGE, NOW, date(2026, 11, 1), None) == (datetime(2026, 11, 1, tzinfo=timezone.utc), None)


# ---- pages -----------------------------------------------------------------------------------------

@pytest.fixture
def twenty_five():
    return FakeBackend(events=[event(n) for n in range(1, 26)])


def test_newest_first_pages(twenty_five):
    api = api_for(twenty_five)
    first = ev.fetch_event_page(api, ev.EventFilters(), 0, 10)
    assert ids(first) == [f"ext-{n}" for n in range(25, 15, -1)]
    assert (first.total, first.pages, first.first_item, first.last_item) == (25, 3, 1, 10)
    last = ev.fetch_event_page(api, ev.EventFilters(), 2, 10)
    assert ids(last) == [f"ext-{n}" for n in range(5, 0, -1)] and (last.first_item, last.last_item) == (21, 25)


def test_oldest_first_pages_are_the_true_oldest_not_a_reversed_newest_page(twenty_five):
    api = api_for(twenty_five)
    assert ids(ev.fetch_event_page(api, ev.EventFilters(), 0, 10, ascending=True)) == [f"ext-{n}" for n in range(1, 11)]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(), 1, 10, ascending=True)) == [f"ext-{n}" for n in range(11, 21)]
    last = ev.fetch_event_page(api, ev.EventFilters(), 2, 10, ascending=True)
    assert ids(last) == [f"ext-{n}" for n in range(21, 26)] and (last.first_item, last.last_item) == (21, 25)


@pytest.mark.parametrize("ascending", [False, True])
def test_every_event_appears_exactly_once_across_all_pages(twenty_five, ascending):
    api = api_for(twenty_five)
    seen = [i for p in range(3) for i in ids(ev.fetch_event_page(api, ev.EventFilters(), p, 10, ascending))]
    assert sorted(seen) == sorted(f"ext-{n}" for n in range(1, 26)) and len(seen) == 25


def test_page_numbers_out_of_range_are_clamped_not_empty(twenty_five):
    api = api_for(twenty_five)
    assert ev.fetch_event_page(api, ev.EventFilters(), 99, 10).page == 2
    assert ev.fetch_event_page(api, ev.EventFilters(), -3, 10).page == 0
    assert ids(ev.fetch_event_page(api, ev.EventFilters(), 99, 10, ascending=True))[0] == "ext-21"


def test_empty_result_is_a_clean_page():
    page = ev.fetch_event_page(api_for(FakeBackend()), ev.EventFilters(), 3, 25)
    assert (page.items, page.total, page.page, page.pages, page.first_item, page.last_item) == ([], 0, 0, 1, 0, 0)


def test_filters_reach_the_api_and_narrow_the_result():
    backend = FakeBackend(events=[
        event(1, severity="critical", source="honeypot", source_ip="203.0.113.9", event_type="sqli_attempt"),
        event(2, severity="high", source="domain", domain="evil.example", event_type="domain_similarity"),
        event(3, severity="high", source="honeypot", source_ip="203.0.113.9", event_type="xss_attempt", at=T0 + timedelta(days=2)),
    ])
    api = api_for(backend)
    assert ids(ev.fetch_event_page(api, ev.EventFilters(severity="high"), 0, 10)) == ["ext-3", "ext-2"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(source="honeypot", severity="high"), 0, 10)) == ["ext-3"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(source_ip="203.0.113.9"), 0, 10)) == ["ext-3", "ext-1"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(domain="evil.example"), 0, 10)) == ["ext-2"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(event_type="sqli_attempt"), 0, 10)) == ["ext-1"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(start_time=T0 + timedelta(days=1)), 0, 10)) == ["ext-3"]
    assert ids(ev.fetch_event_page(api, ev.EventFilters(end_time=T0 + timedelta(days=1)), 0, 10, ascending=True)) == ["ext-1", "ext-2"]
    assert ev.fetch_event_page(api, ev.EventFilters(source="file"), 0, 10).total == 0


def test_event_type_options_are_distinct_and_sorted():
    backend = FakeBackend(events=[event(1, event_type="b_type"), event(2, event_type="a_type"), event(3, event_type="b_type")])
    assert ev.event_type_options(api_for(backend)) == ["a_type", "b_type"]
    assert ev.event_type_options(api_for(FakeBackend())) == []


# ---- related events ----------------------------------------------------------------------------------

def test_related_events_exclude_the_event_itself_and_group_by_shared_field():
    backend = FakeBackend(events=[event(1, source_ip="1.1.1.1", domain="a.example"), event(2, source_ip="1.1.1.1"),
                                  event(3, domain="a.example"), event(4, source_ip="9.9.9.9")])
    me = Event.model_validate(backend.events[0])
    related = ev.related_events(api_for(backend), me)
    assert {k: [e.external_event_id for e in v] for k, v in related.items()} == {
        "source IP 1.1.1.1": ["ext-2"], "domain a.example": ["ext-3"]}


def test_related_events_with_nothing_to_match_on_and_a_cap():
    lonely = Event.model_validate(event(1, url="http://x.example/a"))
    assert ev.related_events(api_for(FakeBackend(events=[event(1)])), lonely) == {}
    crowd = FakeBackend(events=[event(n, source_ip="1.1.1.1") for n in range(1, 40)])
    me = Event.model_validate(crowd.events[0])
    assert len(ev.related_events(api_for(crowd), me)["source IP 1.1.1.1"]) == ev.RELATED_LIMIT


# ---- table rows and detail HTML --------------------------------------------------------------------------

def test_events_table_can_show_a_short_id_column():
    e = Event.model_validate(event(1))
    assert "<th class=\"\">ID</th>" in c.events_table([e], with_id=True) and "00000000" in c.events_table([e], with_id=True)
    assert ">ID<" not in c.events_table([e])


def test_event_detail_shows_every_field_and_escapes():
    e = Event.model_validate(event(1, description="<script>1</script>", source_ip="1.2.3.4", domain="evil.example",
                                   url="http://evil.example/<x>", file_hash="a" * 64))
    html = c.event_detail(e)
    for label in ("Event ID", "External ID", "Source", "Event type", "Severity", "Risk score", "Occurred", "Received", "Description",
                  "Source IP", "Domain", "URL", "File hash (SHA-256)"):
        assert label in html, label
    assert "<script>" not in html and "&lt;script&gt;" in html and "&lt;x&gt;" in html
    assert "Destination IP" not in html                          # absent fields are left out, not shown as blank


def test_risk_factors_table_lists_rules_and_the_total():
    e = Event.model_validate(event(1, risk=60))
    html = c.risk_factors_table(e)
    assert "severity:high" in html and "+40" in html and "<strong>60</strong>" in html
    assert "No risk factors" in c.risk_factors_table(Event.model_validate({**event(1), "risk_factors": []}))


def test_event_indicators_table_and_empty_state():
    from tests.fake_backend import indicator
    with_one = Event.model_validate(event(1, indicators=[indicator(value="1.2.3.4", sightings=4)]))
    assert "1.2.3.4" in c.event_indicators_table(with_one) and "No indicators" in c.event_indicators_table(Event.model_validate(event(2)))
