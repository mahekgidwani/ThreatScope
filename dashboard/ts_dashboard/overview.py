"""Everything the Overview page shows, computed from API answers only.

Counts (total, per severity, per source) are exact: each is the `total` of a filtered `limit=1` query.
The trend and the recent / high-risk lists come from the newest events only (capped at TREND_EVENTS);
when that is fewer than all events, `trend_truncated` is True and the page says so.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.models import Event, Indicator, SEVERITIES, SOURCES
from ts_dashboard.paging import fetch_up_to

TREND_EVENTS = 500
INDICATOR_SCAN = 300
RECENT_EVENTS = 10
HIGH_RISK_EVENTS = 8
TOP_INDICATORS = 8
HIGH_RISK_SEVERITIES = ("critical", "high")
TREND_STEPS = (timedelta(hours=1), timedelta(hours=6), timedelta(days=1), timedelta(days=7), timedelta(days=30))
MAX_TREND_BUCKETS = 60
TREND_WINDOW = TREND_STEPS[-1] * 120     # about 10 years; older events are left off the chart, not stretched over it
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Trend:
    """Events per time bucket, split by severity. `series[severity][i]` belongs to `starts[i]`."""

    starts: list[datetime]
    step: timedelta
    series: dict[str, list[int]]
    outside_range: int = 0      # events too old or too far in the future to chart


@dataclass(frozen=True)
class Overview:
    fetched_at: datetime
    total_events: int
    by_severity: dict[str, int]
    by_source: dict[str, int]
    total_indicators: int
    repeated_indicators: int
    open_incidents: int
    total_incidents: int
    recent_events: list[Event]
    trend: Trend | None
    trend_events_used: int
    trend_truncated: bool
    top_indicators: list[Indicator]
    indicators_scanned: int
    indicators_truncated: bool
    high_risk: list[Event]


def load_overview(api: ThreatScopeApi, now: datetime | None = None) -> Overview:
    """Raises ApiError when any call fails: the page shows one error, never a half-filled screen."""
    now = now or datetime.now(timezone.utc)
    events, total_events = fetch_up_to(api.list_events, TREND_EVENTS)
    by_severity = {s: api.list_events(severity=s, limit=1).total for s in SEVERITIES}
    by_source = {s: api.list_events(source=s, limit=1).total for s in SOURCES}
    indicators, total_indicators = fetch_up_to(api.list_indicators, INDICATOR_SCAN)
    open_incidents = api.list_incidents(status="open", limit=1).total
    total_incidents = api.list_incidents(limit=1).total
    recent_high = [e for sev in HIGH_RISK_SEVERITIES
                   for e in api.list_events(severity=sev, limit=HIGH_RISK_EVENTS).items]
    return Overview(
        fetched_at=now,
        total_events=total_events,
        by_severity=by_severity,
        by_source=by_source,
        total_indicators=total_indicators,
        repeated_indicators=sum(1 for i in indicators if i.sighting_count > 1),
        open_incidents=open_incidents,
        total_incidents=total_incidents,
        recent_events=events[:RECENT_EVENTS],
        trend=build_trend(events, now),
        trend_events_used=len(events),
        trend_truncated=len(events) < total_events,
        top_indicators=top_indicators(indicators),
        indicators_scanned=len(indicators),
        indicators_truncated=len(indicators) < total_indicators,
        high_risk=newest_first(recent_high)[:HIGH_RISK_EVENTS],
    )


def newest_first(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda e: (e.occurred_at, str(e.id)), reverse=True)


def top_indicators(indicators: list[Indicator], limit: int = TOP_INDICATORS) -> list[Indicator]:
    """Indicators seen more than once, most sightings first. Seen once is not 'recurring'."""
    repeated = [i for i in indicators if i.sighting_count > 1]
    return sorted(repeated, key=lambda i: (-i.sighting_count, -i.last_seen.timestamp(), i.value))[:limit]


def _floor(moment: datetime, step: timedelta) -> datetime:
    # timedelta arithmetic, not fromtimestamp(): that raises OSError on Windows for years outside 1970-3000
    return _EPOCH + (moment - _EPOCH) // step * step


def build_trend(events: list[Event], now: datetime) -> Trend | None:
    """Bucket `events` by occurrence time. None when no event is within TREND_WINDOW of `now`. The bucket size is
    the smallest step that keeps the chart under MAX_TREND_BUCKETS bars; empty buckets are kept so gaps are visible.
    Events outside the window are not charted; they are counted in `outside_range`."""
    all_events = events
    events = [e for e in all_events if now - TREND_WINDOW <= e.occurred_at <= now + TREND_STEPS[-1]]
    if not events:
        return None
    first = min(e.occurred_at for e in events)
    last = max(max(e.occurred_at for e in events), now)
    step = TREND_STEPS[-1]
    for candidate in TREND_STEPS:
        if (_floor(last, candidate) - _floor(first, candidate)) / candidate + 1 <= MAX_TREND_BUCKETS:
            step = candidate
            break
    start, end = _floor(first, step), _floor(last, step)
    starts = [start + step * i for i in range(int((end - start) / step) + 1)]
    index = {s: i for i, s in enumerate(starts)}
    series = {sev: [0] * len(starts) for sev in SEVERITIES}
    for event in events:
        series[event.severity][index[_floor(event.occurred_at, step)]] += 1
    return Trend(starts=starts, step=step, series=series, outside_range=len(all_events) - len(events))
