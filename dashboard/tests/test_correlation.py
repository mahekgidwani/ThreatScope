from datetime import timedelta

import pytest

from tests.conftest import make_api
from tests.fake_backend import FakeBackend, T0, event, indicator
from ts_dashboard import components as c
from ts_dashboard import correlation as co
from ts_dashboard.models import Event

IP = indicator(1, "ip", "203.0.113.42", sightings=3)
DOM = indicator(2, "domain", "evil.example", sightings=2)
HASH = indicator(3, "sha256", "a" * 64, sightings=2)


def events(*raw) -> list[Event]:
    return [Event.model_validate(r) for r in raw]


def sample():
    return events(
        event(1, source="honeypot", severity="high", risk=60, indicators=[IP, DOM]),
        event(2, source="domain", severity="medium", risk=40, domain="evil.example", indicators=[DOM]),
        event(3, source="honeypot", severity="critical", risk=95, indicators=[IP]),
        event(4, source="file", severity="low", risk=20, indicators=[HASH]),        # alone: not shared
        event(5, source="file", severity="info", risk=5),                           # no indicators at all
    )


def test_only_indicators_in_two_or_more_events_are_shared():
    clusters = co.correlate(sample())
    assert {k.indicator.value for k in clusters} == {"203.0.113.42", "evil.example"}
    assert all(k.count >= 2 for k in clusters)


def test_cluster_facts_come_from_its_events():
    by_value = {k.indicator.value: k for k in co.correlate(sample())}
    ip, dom = by_value["203.0.113.42"], by_value["evil.example"]
    assert (ip.count, ip.sources, ip.cross_source, ip.max_severity, ip.max_risk) == (2, ["honeypot"], False, "critical", 95)
    assert (dom.count, dom.sources, dom.cross_source, dom.max_severity, dom.max_risk) == (2, ["domain", "honeypot"], True, "high", 60)
    assert [e.external_event_id for e in ip.events] == ["ext-3", "ext-1"]               # newest first
    assert ip.last_seen == ip.events[0].occurred_at


def test_strongest_first_cross_source_then_count_then_risk():
    assert [k.indicator.value for k in co.correlate(sample())] == ["evil.example", "203.0.113.42"]
    busy = indicator(8, "url", "http://busy.example/")
    many = events(*[event(n, severity="low", risk=10, indicators=[busy]) for n in range(101, 106)])
    mixed = many + sample()
    ranked = [k.indicator.value for k in co.correlate(mixed)]
    assert ranked == ["evil.example", "http://busy.example/", "203.0.113.42"]            # cross-source beats 5 events; then count 5 > 2


def test_filters_type_min_events_and_cross_source():
    evts = sample()
    assert [k.indicator.type for k in co.correlate(evts, indicator_type="ip")] == ["ip"]
    assert co.correlate(evts, indicator_type="url") == []
    assert [k.indicator.value for k in co.correlate(evts, cross_source_only=True)] == ["evil.example"]
    assert co.correlate(evts, min_events=3) == []


def test_empty_and_single_event_inputs():
    assert co.correlate([]) == []
    assert co.correlate(events(event(1, indicators=[IP, DOM]))) == []


def test_the_same_event_is_counted_once_per_indicator():
    clusters = co.correlate(events(event(1, indicators=[IP, DOM]), event(2, indicators=[IP, DOM])))
    assert {k.indicator.value: k.count for k in clusters} == {"203.0.113.42": 2, "evil.example": 2}


def test_events_with_indicator():
    assert [e.external_event_id for e in co.events_with_indicator(sample(), 1)] == ["ext-1", "ext-3"]
    assert co.events_with_indicator(sample(), 999) == []


def test_scan_reports_truncation(monkeypatch):
    backend = FakeBackend(events=[event(n) for n in range(1, 8)])
    scan = co.scan_events(make_api(backend)[0], limit=3)
    assert len(scan.events) == 3 and scan.total == 7 and scan.truncated
    full = co.scan_events(make_api(backend)[0])
    assert not full.truncated and len(full.events) == 7


# ---- graph ----------------------------------------------------------------------------------------

def test_graph_edges_are_exactly_the_stored_memberships():
    evts = sample()
    clusters = co.correlate(evts)
    ip = next(k for k in clusters if k.indicator.id == 1)
    graph = co.build_graph(ip, clusters)
    keys = {n.key for n in graph.nodes}
    assert {"i1", "i2", "e" + str(evts[0].id), "e" + str(evts[2].id)} <= keys             # IP, the domain that event 1 also has, both IP events
    edges = set(graph.edges)
    assert ("i1", "e" + str(evts[0].id)) in edges and ("i1", "e" + str(evts[2].id)) in edges
    assert ("i2", "e" + str(evts[0].id)) in edges                                          # event 1 mentions the domain
    assert not any(k.endswith(str(evts[1].id)) for _, k in edges)                          # event 2 is not an event of the IP: no edge, no node
    for indicator_key, event_key in edges:                                                 # nothing invented
        i_id, e_id = int(indicator_key[1:]), event_key[1:]
        assert any(str(e.id) == e_id and any(x.id == i_id for x in e.indicators) for e in evts)


def test_graph_layout_and_labels():
    clusters = co.correlate(sample())
    graph = co.build_graph(clusters[0], clusters)
    assert {n.x for n in graph.nodes if n.kind == "indicator"} == {0.0} and {n.x for n in graph.nodes if n.kind == "event"} == {1.0}
    assert all(0.0 <= n.y <= 1.0 for n in graph.nodes)
    assert all(n.severity for n in graph.nodes if n.kind == "event") and all(n.hover for n in graph.nodes)
    single = co.build_graph(co.correlate(events(event(1, indicators=[IP]), event(2, indicators=[IP])))[0], [])
    assert [n.y for n in single.nodes if n.kind == "indicator"] == [0.5]


def test_graph_is_capped_and_says_how_many_were_left_out():
    crowd = events(*[event(n, indicators=[IP]) for n in range(1, 60)])
    clusters = co.correlate(crowd)
    graph = co.build_graph(clusters[0], clusters)
    assert (graph.events_shown, graph.events_total) == (co.MAX_GRAPH_EVENTS, 59)
    assert sum(1 for n in graph.nodes if n.kind == "event") == co.MAX_GRAPH_EVENTS
    assert graph.nodes[1].label == str(crowd[0].id)[:8]       # newest first


def test_long_indicator_values_are_shortened_in_the_graph_label_but_not_the_hover():
    long_domain = indicator(7, "domain", "x" * 60 + ".example")
    clusters = co.correlate(events(event(1, indicators=[long_domain]), event(2, indicators=[long_domain])))
    node = co.build_graph(clusters[0], clusters).nodes[0]
    assert node.label.endswith("…") and len(node.label) <= 28 and "x" * 60 in node.hover


# ---- html -----------------------------------------------------------------------------------------

def test_clusters_table_shows_sources_cross_source_tag_and_escapes():
    hostile = indicator(9, "domain", "<script>x</script>.example")
    clusters = co.correlate(events(event(1, source="domain", indicators=[hostile, DOM]), event(2, source="honeypot", indicators=[hostile, DOM])))
    html = c.clusters_table(clusters)
    assert "cross-source" in html and "Honeypot" in html and "Domain" in html and "Highest severity" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "cross-source" not in c.clusters_table(co.correlate(events(event(1, indicators=[IP]), event(2, indicators=[IP]))))
