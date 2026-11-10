"""Correlation: which indicators appear in more than one event, and how events connect through them.

Built only from what the API returns: every event carries the indicators the backend extracted from it, so an
indicator that appears in two events IS a stored relationship (same IP, domain, URL or hash). Nothing here
scores or guesses; "shared" means "the same value was observed in several events", not "the same actor".

The API cannot list events by indicator for urls and hashes, so we read the newest EVENT_SCAN events once and
group them. `Scan.truncated` says when that is fewer than all events, and the page says so too.
"""
from dataclasses import dataclass
from datetime import datetime

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.models import Event, Indicator, SEVERITIES
from ts_dashboard.paging import fetch_up_to
from ts_dashboard.redact import redact

EVENT_SCAN = 1000
MAX_GRAPH_EVENTS = 30
_RANK = {severity: i for i, severity in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Scan:
    events: list[Event]      # newest first
    total: int

    @property
    def truncated(self) -> bool:
        return len(self.events) < self.total


def scan_events(api: ThreatScopeApi, limit: int = EVENT_SCAN) -> Scan:
    events, total = fetch_up_to(api.list_events, limit)
    return Scan(events, total)


@dataclass(frozen=True)
class Cluster:
    """One shared indicator and the events that mention it (newest first)."""

    indicator: Indicator
    events: list[Event]

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def sources(self) -> list[str]:
        return sorted({e.source for e in self.events})

    @property
    def cross_source(self) -> bool:
        return len(self.sources) > 1

    @property
    def max_severity(self) -> str:
        return max((e.severity for e in self.events), key=_RANK.__getitem__)

    @property
    def max_risk(self) -> int:
        return max(e.risk_score for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(e.occurred_at for e in self.events)


def events_with_indicator(events: list[Event], indicator_id: int) -> list[Event]:
    return [e for e in events if any(i.id == indicator_id for i in e.indicators)]


def correlate(events: list[Event], min_events: int = 2, indicator_type: str | None = None,
              cross_source_only: bool = False) -> list[Cluster]:
    """Indicators found in at least `min_events` events, strongest first: cross-source, then most events, then highest risk."""
    members: dict[int, tuple[Indicator, list[Event]]] = {}
    for event in events:
        for indicator in event.indicators:
            members.setdefault(indicator.id, (indicator, []))[1].append(event)
    clusters = [Cluster(indicator, sorted(found, key=lambda e: (e.occurred_at, str(e.id)), reverse=True))
                for indicator, found in members.values() if len(found) >= min_events]
    if indicator_type:
        clusters = [c for c in clusters if c.indicator.type == indicator_type]
    if cross_source_only:
        clusters = [c for c in clusters if c.cross_source]
    return sorted(clusters, key=lambda c: (not c.cross_source, -c.count, -c.max_risk, c.indicator.value))


# ---- relationship graph -------------------------------------------------------------------------

@dataclass(frozen=True)
class Node:
    key: str
    kind: str            # 'indicator' or 'event'
    label: str
    hover: str
    x: float
    y: float
    severity: str | None = None


@dataclass(frozen=True)
class Graph:
    nodes: list[Node]
    edges: list[tuple[str, str]]      # (indicator node key, event node key)
    events_shown: int
    events_total: int


def _spread(count: int) -> list[float]:
    return [0.5] if count == 1 else [1 - i / (count - 1) for i in range(count)]


def build_graph(selected: Cluster, clusters: list[Cluster]) -> Graph:
    """Two columns: indicators on the left, events on the right, a line wherever an event mentions an indicator.
    Shows the selected indicator, its events (newest MAX_GRAPH_EVENTS), and every OTHER shared indicator that
    those events also mention, so chains such as 'same IP, and the same domain' are visible."""
    events = selected.events[:MAX_GRAPH_EVENTS]
    shown_ids = {e.id for e in events}
    related = [c for c in clusters if c.indicator.id != selected.indicator.id and any(e.id in shown_ids for e in c.events)]
    indicator_clusters = [selected, *related]
    ys_ind, ys_evt = _spread(len(indicator_clusters)), _spread(len(events))
    nodes: list[Node] = []
    edges: list[tuple[str, str]] = []
    for cluster, y in zip(indicator_clusters, ys_ind):
        ind = cluster.indicator
        value = redact(ind.value)
        nodes.append(Node(f"i{ind.id}", "indicator", value if len(value) <= 28 else value[:27] + "…",
                          f"{ind.type}: {value}<br>{cluster.count} events in this view · {ind.sighting_count} sightings",
                          0.0, y))
        edges += [(f"i{ind.id}", f"e{e.id}") for e in cluster.events if e.id in shown_ids]
    for event, y in zip(events, ys_evt):
        nodes.append(Node(f"e{event.id}", "event", str(event.id)[:8],
                          f"{event.event_type}<br>{event.source} · {event.severity} · risk {event.risk_score}<br>{event.id}",
                          1.0, y, event.severity))
    return Graph(nodes, edges, len(events), selected.count)
