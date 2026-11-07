"""Chart data preparation, checked on the figures themselves. Needs plotly (installed on the host, not in the backend image)."""
import json
from datetime import timedelta

from tests.fake_backend import T0, event
from ts_dashboard import charts
from ts_dashboard.models import Event
from ts_dashboard.overview import build_trend
from ts_dashboard.theme import COLORS, SEVERITY_COLOURS, SEVERITY_LABELS


def trend_of(*raw, now=None):
    return build_trend([Event.model_validate(r) for r in raw], now or T0 + timedelta(hours=3))


def test_trend_figure_has_one_stacked_trace_per_present_severity_with_the_severity_colour():
    fig = charts.trend_figure(trend_of(event(1, severity="high"), event(2, severity="high"), event(3, severity="critical")))
    assert {t.name: t.marker.color for t in fig.data} == {"High": SEVERITY_COLOURS["high"], "Critical": SEVERITY_COLOURS["critical"]}
    assert fig.layout.barmode == "stack" and fig.layout.showlegend
    assert sum(sum(t.y) for t in fig.data) == 3
    assert list(fig.data[0].x) == list(fig.data[1].x)            # same buckets on every trace


def test_trend_figure_axis_is_integer_for_small_counts():
    assert charts.trend_figure(trend_of(event(1))).layout.yaxis.dtick == 1


def test_severity_figure_lists_critical_first_with_all_five_levels_and_exact_values():
    counts = {"info": 0, "low": 1, "medium": 0, "high": 2, "critical": 3}
    fig = charts.severity_figure(counts)
    bar = fig.data[0]
    assert list(bar.y) == [SEVERITY_LABELS[s] for s in ("critical", "high", "medium", "low", "info")]
    assert list(bar.x) == [3, 2, 0, 1, 0]
    assert list(bar.marker.color) == [SEVERITY_COLOURS[s] for s in ("critical", "high", "medium", "low", "info")]


def test_source_figure_sorts_by_count_and_keeps_zero_sources():
    fig = charts.source_figure({"domain": 1, "honeypot": 5, "file": 0, "network": 0})
    assert list(fig.data[0].y) == ["Honeypot", "Domain", "File", "Network"] and list(fig.data[0].x) == [5, 1, 0, 0]
    assert set(fig.data[0].marker.color) == {COLORS["accent_muted"]}   # cyan is reserved for selection and trend


def test_all_zero_counts_still_build_a_valid_figure():
    assert list(charts.severity_figure({s: 0 for s in SEVERITY_LABELS}).layout.xaxis.range) == [0, 1]


def test_figures_are_plain_serialisable_json_and_transparent():
    fig = charts.source_figure({"domain": 1})
    json.loads(fig.to_json())
    assert fig.layout.paper_bgcolor == "rgba(0,0,0,0)" and charts.CHART_CONFIG["displayModeBar"] is False


def test_graph_figure_draws_one_line_per_membership_and_colours_events_by_severity():
    from tests.fake_backend import indicator
    from ts_dashboard.correlation import build_graph, correlate
    ip = indicator(1, "ip", "1.2.3.4")
    clusters = correlate([Event.model_validate(event(1, severity="high", indicators=[ip])),
                          Event.model_validate(event(2, severity="critical", indicators=[ip]))])
    graph = build_graph(clusters[0], clusters)
    fig = charts.graph_figure(graph)
    lines = fig.data[0]
    assert len([v for v in lines.x if v is not None]) == 2 * len(graph.edges) and lines.mode == "lines"
    names = {t.name: t.marker.color for t in fig.data[1:]}
    assert names == {"Shared indicator": COLORS["accent"], "Event · Critical": SEVERITY_COLOURS["critical"], "Event · High": SEVERITY_COLOURS["high"]}
    assert fig.data[1].marker.symbol == "diamond" and fig.layout.xaxis.visible is False
    assert fig.layout.height >= 300
