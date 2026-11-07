"""Event creation, retrieval and listing. Runs on SQLite and on real PostgreSQL."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.enums import IndicatorType, Severity, Source
from app.errors import DuplicateEventError, InvalidFilterError, NotFoundError
from app.models import Event, EventIndicator, Incident, Indicator
from app.schemas.event import EventIn
from app.services import event_service
from app.services.event_service import EventFilters, create_event, get_event, list_events
from app.services.incident_service import list_incidents
from app.services.indicator_service import list_indicators

UTC = timezone.utc
BASE = dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
            severity="high", description="probe")


def payload(**over) -> EventIn:
    return EventIn(**{**BASE, **over})


def count(session, model) -> int:
    return session.scalar(select(func.count()).select_from(model))


def ids(events) -> list[uuid.UUID]:
    return [e.id for e in events]


# ---- create --------------------------------------------------------------------

def test_create_stores_event_indicators_and_risk(session):
    before = datetime.now(UTC)
    ev = create_event(session, payload(source_ip="203.0.113.42", url="http://evil.example/a"))
    after = datetime.now(UTC)

    assert isinstance(ev.id, uuid.UUID)
    assert before <= ev.received_at <= after
    assert ev.risk_score == 55                       # high 40 + honeypot 15 + first sighting 0
    assert ev.risk_factors == [{"rule": "severity:high", "points": 40},
                               {"rule": "source:honeypot", "points": 15}]
    assert {(i.type, i.value) for i in ev.indicators} == {
        ("ip", "203.0.113.42"), ("url", "http://evil.example/a"), ("domain", "evil.example")}
    assert all(i.sighting_count == 1 for i in ev.indicators)
    assert count(session, EventIndicator) == 3


def test_event_without_indicators_is_stored_with_no_links(session):
    ev = create_event(session, payload())
    assert ev.indicators == [] and ev.risk_score == 55
    assert count(session, Indicator) == 0


def test_repeat_bonus_schedule_across_events(session):
    scores, counts, factor_names = [], [], []
    for _ in range(6):
        ev = create_event(session, payload(source_ip="203.0.113.42"))
        scores.append(ev.risk_score)
        counts.append(ev.indicators[0].sighting_count)
        factor_names.append([f["rule"] for f in ev.risk_factors])
    assert counts == [1, 2, 3, 4, 5, 6]
    assert scores == [55, 60, 65, 70, 75, 75]      # +0, +5, +10, +15, +20, +20 (cap)
    assert "repeat_indicator" not in factor_names[0]      # first sighting: no bonus
    assert all("repeat_indicator" in names for names in factor_names[1:])


def test_most_seen_indicator_drives_the_bonus(session):
    for _ in range(3):
        create_event(session, payload(source_ip="203.0.113.42"))
    fresh_domain_and_busy_ip = create_event(session, payload(source_ip="203.0.113.42", domain="new.example"))
    assert fresh_domain_and_busy_ip.risk_score == 55 + 15   # the busy IP was seen 3 times before


def test_indicator_repeated_within_one_event_counts_once(session):
    ev = create_event(session, payload(domain="evil.example", url="http://evil.example/a"))
    by_type = {(i.type, i.value): i for i in ev.indicators}
    assert by_type[("domain", "evil.example")].sighting_count == 1
    assert ev.risk_score == 55
    assert count(session, EventIndicator) == 2          # domain + url, not 3


def test_occurred_at_and_received_at_are_independent(session):
    ev = create_event(session, payload(occurred_at="2020-01-02T03:04:05+05:30"))
    assert ev.occurred_at == datetime(2020, 1, 1, 21, 34, 5, tzinfo=UTC)
    assert ev.received_at > datetime(2026, 1, 1, tzinfo=UTC)


def test_metadata_and_fields_are_stored_as_sent(session):
    meta = {"rule": "9500001", "tags": ["xss"], "nested": {"ünï": "値"}}
    ev = create_event(session, payload(metadata=meta, external_event_id="ext-1", destination_ip="198.51.100.9",
                                       file_hash="AB" * 32))
    session.expunge_all()
    stored = get_event(session, ev.id)
    assert stored.event_metadata == meta
    assert (stored.external_event_id, stored.destination_ip, stored.file_hash) == ("ext-1", "198.51.100.9", "ab" * 32)
    assert (stored.source, stored.severity) == ("honeypot", "high")


def test_duplicate_external_id_raises_and_leaves_no_partial_rows(session):
    first = create_event(session, payload(external_event_id="ext-1", source_ip="203.0.113.42"))
    with pytest.raises(DuplicateEventError) as exc:
        create_event(session, payload(external_event_id="ext-1", source_ip="203.0.113.42", domain="other.example"))
    assert exc.value.existing_id == first.id
    assert count(session, Event) == 1
    assert count(session, Indicator) == 1                      # "other.example" was not created
    assert session.scalar(select(Indicator.sighting_count)) == 1   # and the shared IP was not counted again
    # the session must still be usable afterwards
    assert create_event(session, payload(external_event_id="ext-2")).id != first.id


def test_same_external_id_on_another_source_is_not_a_duplicate(session):
    create_event(session, payload(external_event_id="ext-1"))
    create_event(session, payload(external_event_id="ext-1", source="domain"))
    assert count(session, Event) == 2


def test_without_external_id_events_are_never_duplicates(session):
    create_event(session, payload())
    create_event(session, payload())
    assert count(session, Event) == 2


def test_failure_halfway_rolls_back_everything(session, monkeypatch):
    real = event_service._record_sighting
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(*args, **kwargs)

    monkeypatch.setattr(event_service, "_record_sighting", flaky)
    with pytest.raises(RuntimeError):
        create_event(session, payload(source_ip="203.0.113.42", domain="evil.example"))
    assert (count(session, Event), count(session, Indicator), count(session, EventIndicator)) == (0, 0, 0)


def test_other_integrity_errors_are_not_reported_as_duplicates(session, monkeypatch):
    monkeypatch.setattr(event_service, "compute_risk", lambda *a, **k: (101, []))   # breaks the 0..100 CHECK
    with pytest.raises(IntegrityError):
        create_event(session, payload(external_event_id="ext-1"))
    assert count(session, Event) == 0


# ---- get -----------------------------------------------------------------------

def test_get_event_round_trip_and_not_found(session):
    created = create_event(session, payload(source_ip="203.0.113.42"))
    session.expunge_all()
    loaded = get_event(session, created.id)
    assert loaded.id == created.id and [i.value for i in loaded.indicators] == ["203.0.113.42"]
    with pytest.raises(NotFoundError):
        get_event(session, uuid.uuid4())


# ---- list: filters -------------------------------------------------------------

@pytest.fixture
def seeded(session):
    e1 = create_event(session, payload(event_type="xss_attempt", severity="high", source_ip="203.0.113.1",
                                       domain="a.example", occurred_at="2026-11-07T10:00:00Z"))
    e2 = create_event(session, payload(event_type="sqli_attempt", severity="critical", source_ip="203.0.113.2",
                                       domain="b.example", occurred_at="2026-11-07T11:00:00Z"))
    e3 = create_event(session, payload(source="domain", event_type="typosquat_match", severity="low",
                                       domain="c.example", occurred_at="2026-11-07T12:00:00Z"))
    e4 = create_event(session, payload(source="network", event_type="port_scan", severity="medium",
                                       source_ip="203.0.113.1", occurred_at="2026-11-07T13:00:00Z"))
    return e1, e2, e3, e4


def test_each_filter_selects_the_right_events(session, seeded):
    e1, e2, e3, e4 = seeded

    def found(**f):
        events, total = list_events(session, EventFilters(**f), limit=50, offset=0)
        assert total == len(events)
        return set(ids(events))

    assert found(source=Source.honeypot) == {e1.id, e2.id}
    assert found(source=Source.network) == {e4.id}
    assert found(event_type="sqli_attempt") == {e2.id}
    assert found(severity=Severity.low) == {e3.id}
    assert found(source_ip="203.0.113.1") == {e1.id, e4.id}
    assert found(domain="b.example") == {e2.id}
    assert found(start_time=datetime(2026, 11, 7, 11, 0, tzinfo=UTC)) == {e2.id, e3.id, e4.id}
    assert found(end_time=datetime(2026, 11, 7, 12, 0, tzinfo=UTC)) == {e1.id, e2.id}
    assert found() == {e1.id, e2.id, e3.id, e4.id}


def test_filters_combine_with_and(session, seeded):
    e1, *_ = seeded
    events, total = list_events(session, EventFilters(source=Source.honeypot, source_ip="203.0.113.1",
                                                      severity=Severity.high), 50, 0)
    assert ids(events) == [e1.id] and total == 1
    assert list_events(session, EventFilters(source=Source.network, severity=Severity.high), 50, 0) == ([], 0)


def test_time_range_start_is_inclusive_and_end_is_exclusive(session, seeded):
    e1, e2, e3, _ = seeded
    start, end = datetime(2026, 11, 7, 10, 0, tzinfo=UTC), datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    events, total = list_events(session, EventFilters(start_time=start, end_time=end), 50, 0)
    assert set(ids(events)) == {e1.id, e2.id} and total == 2      # e1 at 10:00 in, e3 at 12:00 out
    ist = timezone(timedelta(hours=5, minutes=30))
    same_instant = datetime(2026, 11, 7, 15, 30, tzinfo=ist)       # == 10:00 UTC
    assert set(ids(list_events(session, EventFilters(start_time=same_instant, end_time=end), 50, 0)[0])) == {e1.id, e2.id}


def test_domain_filter_uses_the_same_normalisation_as_ingestion(session):
    ev = create_event(session, payload(domain="Bücher.example"))
    for spelling in ("BÜCHER.example", "xn--bcher-kva.example", "bücher.example."):
        assert ids(list_events(session, EventFilters(domain=spelling), 50, 0)[0]) == [ev.id], spelling
    create_event(session, payload(domain="apple.com"))
    assert list_events(session, EventFilters(domain="аpple.com"), 50, 0)[1] == 0   # Cyrillic 'а' != Latin 'a'


def test_ip_filter_uses_the_canonical_form(session):
    ev = create_event(session, payload(source_ip="2001:0DB8:0:0:0:0:0:1"))
    assert ids(list_events(session, EventFilters(source_ip="2001:db8::1"), 50, 0)[0]) == [ev.id]
    assert ids(list_events(session, EventFilters(source_ip="2001:0DB8::0001"), 50, 0)[0]) == [ev.id]


def test_wildcard_characters_in_filters_are_literal(session):
    create_event(session, payload(domain="a.example", event_type="probe_a"))
    create_event(session, payload(domain="b.example", event_type="probe_b"))
    # event_type is compared exactly, so SQL wildcards match nothing instead of everything.
    for pattern in ("%", "probe_%", "probe__", "_robe_a", "probe_a%"):
        assert list_events(session, EventFilters(event_type=pattern), 50, 0) == ([], 0), pattern
    assert list_events(session, EventFilters(event_type="probe_a"), 50, 0)[1] == 1
    # '%' and '_' can never appear in a valid hostname, so domain filters containing them are rejected outright.
    for pattern in ("%", "_.example", "%.example"):
        with pytest.raises(InvalidFilterError):
            list_events(session, EventFilters(domain=pattern), 50, 0)


@pytest.mark.parametrize("bad", [
    dict(start_time=datetime(2026, 11, 7, 10, 0)),                    # naive
    dict(end_time=datetime(2026, 11, 7, 10, 0)),                      # naive
    dict(start_time=datetime(2026, 11, 8, tzinfo=UTC), end_time=datetime(2026, 11, 7, tzinfo=UTC)),
    dict(domain="bad_domain!.com"), dict(source_ip="999.1.1.1"), dict(source_ip="%"),
], ids=["naive-start", "naive-end", "start-after-end", "bad-domain", "bad-ip", "wildcard-ip"])
def test_invalid_filters_raise_invalid_filter_error(session, bad):
    with pytest.raises(InvalidFilterError):
        list_events(session, EventFilters(**bad), 50, 0)


@pytest.mark.parametrize("limit,offset", [(0, 0), (101, 0), (-1, 0), (50, -1)])
def test_invalid_paging_raises_invalid_filter_error(session, limit, offset):
    with pytest.raises(InvalidFilterError):
        list_events(session, EventFilters(), limit, offset)


def test_start_equal_to_end_is_an_empty_range_not_an_error(session, seeded):
    t = datetime(2026, 11, 7, 11, 0, tzinfo=UTC)
    assert list_events(session, EventFilters(start_time=t, end_time=t), 50, 0) == ([], 0)


# ---- list: paging and order ----------------------------------------------------

def test_paging_and_newest_first_order(session):
    created = [create_event(session, payload(occurred_at=f"2026-11-07T{10 + h}:00:00Z")) for h in range(5)]
    newest_first = [e.id for e in reversed(created)]

    page, total = list_events(session, EventFilters(), limit=2, offset=2)
    assert total == 5 and ids(page) == newest_first[2:4]
    assert ids(list_events(session, EventFilters(), 100, 0)[0]) == newest_first
    assert list_events(session, EventFilters(), 2, 4)[0] == list_events(session, EventFilters(), 100, 4)[0]
    assert ids(list_events(session, EventFilters(), 2, 5)[0]) == [] and list_events(session, EventFilters(), 2, 5)[1] == 5


def test_equal_timestamps_are_ordered_by_id_descending(session):
    created = [create_event(session, payload()) for _ in range(4)]       # identical occurred_at
    assert ids(list_events(session, EventFilters(), 50, 0)[0]) == sorted(ids(created), reverse=True)


def test_listed_events_carry_their_indicators(session):
    create_event(session, payload(source_ip="203.0.113.42", domain="evil.example"))
    session.expunge_all()
    events, _ = list_events(session, EventFilters(), 50, 0)
    session.close()                                  # indicators must already be loaded
    assert {i.value for i in events[0].indicators} == {"203.0.113.42", "evil.example"}


# ---- indicators and incidents --------------------------------------------------

def test_list_indicators_filters_orders_and_pages(session):
    create_event(session, payload(source_ip="203.0.113.1", domain="a.example"))
    create_event(session, payload(source_ip="203.0.113.1", domain="b.example"))
    create_event(session, payload(source_ip="203.0.113.2"))

    everything, total = list_indicators(session, None, None, limit=50, offset=0)
    assert total == 4 and len(everything) == 4
    ips, total_ips = list_indicators(session, IndicatorType.ip, None, 50, 0)
    assert total_ips == 2 and {i.value for i in ips} == {"203.0.113.1", "203.0.113.2"}
    one, total_one = list_indicators(session, IndicatorType.ip, "203.0.113.1", 50, 0)
    assert total_one == 1 and one[0].sighting_count == 2
    assert list_indicators(session, None, "%", 50, 0) == ([], 0)
    page, total_all = list_indicators(session, None, None, limit=3, offset=3)
    assert len(page) == 1 and total_all == 4
    with pytest.raises(InvalidFilterError):
        list_indicators(session, None, None, 101, 0)


def test_list_incidents_empty_then_filtered_by_status(session):
    assert list_incidents(session, None, 50, 0) == ([], 0)
    session.add_all([Incident(title="a", severity="high", status="open"),
                     Incident(title="b", severity="low", status="closed")])
    session.commit()
    assert list_incidents(session, None, 50, 0)[1] == 2
    open_only, total = list_incidents(session, "open", 50, 0)
    assert total == 1 and open_only[0].title == "a"
    with pytest.raises(InvalidFilterError):
        list_incidents(session, "bogus", 50, 0)
    with pytest.raises(InvalidFilterError):
        list_incidents(session, None, 0, 0)


# ---- review fixes: inputs PostgreSQL cannot represent --------------------------

@pytest.mark.parametrize("bad", [
    dict(event_type="\x00"), dict(event_type="a\x00b"),
    dict(source_ip="fe80::1%eth0"), dict(source_ip="fe80::1%" + "a" * 60),
    dict(start_time=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5, minutes=30)))),     # overflows when made UTC
    dict(end_time=datetime(9999, 12, 31, 23, 30, tzinfo=timezone(timedelta(hours=-1)))),
], ids=["nul", "nul-inside", "ipv6-scope", "ipv6-long-scope", "year-1-overflow", "year-9999-overflow"])
def test_filters_the_database_cannot_represent_are_invalid_filters(session, bad):
    with pytest.raises(InvalidFilterError):
        list_events(session, EventFilters(**bad), 50, 0)


def test_the_biggest_offset_is_accepted_and_just_returns_nothing(session):
    create_event(session, payload())
    assert list_events(session, EventFilters(), 50, 2**63 - 1) == ([], 1)
    with pytest.raises(InvalidFilterError):
        list_events(session, EventFilters(), 50, 2**63)


def test_indicator_and_incident_paging_has_the_same_offset_bound(session):
    assert list_indicators(session, None, None, 50, 2**63 - 1) == ([], 0)
    assert list_incidents(session, None, 50, 2**63 - 1) == ([], 0)
    with pytest.raises(InvalidFilterError):
        list_indicators(session, None, None, 50, 2**63)
    with pytest.raises(InvalidFilterError):
        list_incidents(session, None, 50, 2**63)


def test_indicator_value_filter_rejects_nul(session):
    with pytest.raises(InvalidFilterError):
        list_indicators(session, None, "a\x00b", 50, 0)
