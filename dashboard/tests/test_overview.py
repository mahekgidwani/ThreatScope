from datetime import datetime, timedelta, timezone

import pytest

from tests.fake_backend import FakeBackend, T0, event, incident, indicator
from tests.conftest import make_api
from ts_dashboard import overview as ov
from ts_dashboard.api_client import ApiConnectionError
from ts_dashboard.models import Event
from ts_dashboard.paging import fetch_up_to

NOW = T0 + timedelta(hours=9)


def api_for(backend: FakeBackend):
    api, _ = make_api(backend)
    return api


def parsed(*raw):
    return [Event.model_validate(r) for r in raw]


# ---- paging -----------------------------------------------------------------------------

def test_fetch_up_to_reads_several_pages_and_reports_the_true_total():
    backend = FakeBackend(events=[event(n) for n in range(1, 251)])
    items, total = fetch_up_to(api_for(backend).list_events, 230)
    assert (len(items), total) == (230, 250)
    assert [dict(r.url.params)["offset"] for r in backend.requests] == ["0", "100", "200"]
    assert dict(backend.requests[-1].url.params)["limit"] == "30"   # never asks for more than it still needs


def test_fetch_up_to_stops_when_the_data_ends_and_handles_empty():
    items, total = fetch_up_to(api_for(FakeBackend(events=[event(1), event(2)])).list_events, 500)
    assert (len(items), total) == (2, 2)
    assert fetch_up_to(api_for(FakeBackend()).list_events, 500) == ([], 0)


def test_fetch_up_to_passes_filters_through():
    backend = FakeBackend(events=[event(1, severity="low"), event(2, severity="high")])
    items, total = fetch_up_to(api_for(backend).list_events, 10, severity="high")
    assert [e.severity for e in items] == ["high"] and total == 1


# ---- load_overview -----------------------------------------------------------------------

def test_empty_backend():
    data = ov.load_overview(api_for(FakeBackend()), NOW)
    assert data.total_events == 0 and data.total_indicators == 0 and data.open_incidents == 0 and data.total_incidents == 0
    assert data.trend is None and data.recent_events == [] and data.high_risk == [] and data.top_indicators == []
    assert set(data.by_severity.values()) == {0} and set(data.by_source.values()) == {0}
    assert not data.trend_truncated and not data.indicators_truncated


def test_counts_are_exact_and_cover_every_severity_and_source():
    events = ([event(n, severity="critical", source="honeypot") for n in range(1, 4)]
              + [event(n, severity="high", source="domain") for n in range(4, 6)]
              + [event(6, severity="low", source="file")])
    data = ov.load_overview(api_for(FakeBackend(events=events)), NOW)
    assert data.total_events == 6
    assert data.by_severity == {"info": 0, "low": 1, "medium": 0, "high": 2, "critical": 3}
    assert data.by_source == {"domain": 2, "honeypot": 3, "file": 1, "network": 0}


def test_counts_stay_exact_when_the_trend_sample_is_cut(monkeypatch):
    monkeypatch.setattr(ov, "TREND_EVENTS", 5)
    data = ov.load_overview(api_for(FakeBackend(events=[event(n, severity="high") for n in range(1, 13)])), NOW)
    assert data.total_events == 12 and data.by_severity["high"] == 12
    assert data.trend_truncated and data.trend_events_used == 5
    assert sum(sum(v) for v in data.trend.series.values()) == 5


def test_recent_events_are_newest_first_and_capped():
    data = ov.load_overview(api_for(FakeBackend(events=[event(n) for n in range(1, 31)])), NOW)
    assert len(data.recent_events) == 10
    assert [e.external_event_id for e in data.recent_events[:2]] == ["ext-30", "ext-29"]


def test_high_risk_merges_critical_and_high_newest_first():
    events = [event(1, severity="critical"), event(2, severity="high"), event(3, severity="medium"),
              event(4, severity="critical"), event(5, severity="low")]
    data = ov.load_overview(api_for(FakeBackend(events=events)), NOW)
    assert [e.external_event_id for e in data.high_risk] == ["ext-4", "ext-2", "ext-1"]


def test_incident_counts():
    backend = FakeBackend(incidents=[incident(1, "open"), incident(2, "closed"), incident(3, "open")])
    data = ov.load_overview(api_for(backend), NOW)
    assert (data.open_incidents, data.total_incidents) == (2, 3)


def test_api_failure_propagates_as_an_api_error():
    with pytest.raises(ApiConnectionError):
        ov.load_overview(api_for(FakeBackend(down=True)), NOW)


def test_overview_only_reads():
    backend = FakeBackend(events=[event(1)])
    ov.load_overview(api_for(backend), NOW)
    assert {r.method for r in backend.requests} == {"GET"}


# ---- top indicators ---------------------------------------------------------------------------

def test_top_indicators_exclude_single_sightings_and_sort_by_count():
    from ts_dashboard.models import Indicator
    rows = [indicator(1, value="a.example", type="domain", sightings=1), indicator(2, value="1.1.1.1", sightings=5),
            indicator(3, value="2.2.2.2", sightings=3), indicator(4, value="3.3.3.3", sightings=3, last=T0 + timedelta(hours=1))]
    top = ov.top_indicators([Indicator.model_validate(r) for r in rows])
    assert [i.value for i in top] == ["1.1.1.1", "3.3.3.3", "2.2.2.2"]      # tie broken by most recent
    assert ov.top_indicators([], 5) == [] and len(ov.top_indicators([Indicator.model_validate(r) for r in rows], 1)) == 1


def test_indicator_scan_reports_truncation(monkeypatch):
    monkeypatch.setattr(ov, "INDICATOR_SCAN", 3)
    backend = FakeBackend(indicators=[indicator(n, value=f"10.0.0.{n}", sightings=2) for n in range(1, 8)])
    data = ov.load_overview(api_for(backend), NOW)
    assert data.total_indicators == 7 and data.indicators_scanned == 3 and data.indicators_truncated
    assert data.repeated_indicators == 3


# ---- trend ---------------------------------------------------------------------------------------

def test_trend_none_without_events():
    assert ov.build_trend([], NOW) is None


def test_trend_hourly_buckets_zero_fill_and_severity_split():
    events = parsed(event(1, severity="high", at=T0 + timedelta(minutes=10)), event(2, severity="high", at=T0 + timedelta(minutes=50)),
                    event(3, severity="critical", at=T0 + timedelta(hours=3, minutes=5)))
    trend = ov.build_trend(events, T0 + timedelta(hours=4, minutes=30))
    assert trend.step == timedelta(hours=1) and len(trend.starts) == 5            # 04:00 .. 08:00
    assert trend.starts[0] == T0 and trend.starts[-1] == T0 + timedelta(hours=4)
    assert trend.series["high"] == [2, 0, 0, 0, 0] and trend.series["critical"] == [0, 0, 0, 1, 0]
    assert all(sum(v) == 0 for k, v in trend.series.items() if k not in ("high", "critical"))


def test_trend_range_reaches_now_even_with_old_events():
    trend = ov.build_trend(parsed(event(1, at=T0)), T0 + timedelta(hours=6))
    assert trend.starts[-1] == T0 + timedelta(hours=6)


@pytest.mark.parametrize("span, step", [(timedelta(hours=40), timedelta(hours=1)), (timedelta(days=6), timedelta(hours=6)),
                                         (timedelta(days=40), timedelta(days=1)), (timedelta(days=300), timedelta(days=7)),
                                         (timedelta(days=3000), timedelta(days=30))])
def test_trend_step_grows_with_the_span_and_bars_stay_bounded(span, step):
    trend = ov.build_trend(parsed(event(1, at=T0), event(2, at=T0 + span)), T0 + span)
    assert trend.step == step
    if step != timedelta(days=30):   # the largest step is the fallback and may exceed the bar budget
        assert len(trend.starts) <= ov.MAX_TREND_BUCKETS
    assert sum(sum(v) for v in trend.series.values()) == 2


def test_trend_counts_every_event_exactly_once():
    events = parsed(*[event(n, severity=("low", "high", "info")[n % 3], at=T0 + timedelta(minutes=37 * n)) for n in range(1, 60)])
    trend = ov.build_trend(events, NOW)
    assert sum(sum(v) for v in trend.series.values()) == 59
