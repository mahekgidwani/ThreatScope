from datetime import datetime, timedelta, timezone

import pytest

from tests.fake_backend import T0, event, indicator
from ts_dashboard import components as c
from ts_dashboard import correlation as co
from ts_dashboard.models import Event, Health, Indicator
from ts_dashboard.theme import SEVERITY_COLOURS, css

EVIL = '<img src=x onerror=alert(1)>"\'&'


def parsed(**kw) -> Event:
    return Event.model_validate(event(1, **kw))


def test_event_text_is_escaped_everywhere():
    e = parsed(description=EVIL, event_type="a<b", source_ip=None, domain="evil.example</td><script>")
    html = c.events_table([e]) + c.high_risk_table([e])
    assert "<img" not in html and "<script" not in html and "onerror=alert(1)>" not in html
    assert "&lt;img" in html


def test_indicator_values_are_escaped():
    row = Indicator.model_validate(indicator(value="<b>x</b>"))
    assert "<b>x</b>" not in c.indicators_table([row]) and "&lt;b&gt;x" in c.indicators_table([row])


@pytest.mark.parametrize("fn", [c.empty_state, c.error_state])
def test_state_panels_escape(fn):
    html = fn("<i>t</i>", "<script>x</script>")
    assert "<script>" not in html and "<i>t</i>" not in html


def test_kpi_card_escapes_and_formats():
    html = c.kpi_card("<b>L</b>", 12345, "ctx<script>", "critical")
    assert "12,345" in html and "<script>" not in html and "<b>L</b>" not in html and "sev-critical" in html
    assert "sev-" not in c.kpi_card("L", 1, "x")


def test_kpi_figure_takes_the_severity_colour_only_when_above_zero():
    assert "lit" in c.kpi_card("Critical", 2, "x", "critical").split("ts-kpi-value")[1].split(">")[0]
    zero = c.kpi_card("Critical", 0, "x", "critical")
    assert "lit" not in zero.split("ts-kpi-value")[1].split(">")[0] and "sev-critical" in zero   # dot keeps the colour


def test_severity_badge_has_text_and_class_and_survives_unknown_values():
    assert "High" in c.severity_badge("high") and "sev-high" in c.severity_badge("high")
    unknown = c.severity_badge("<weird>")
    assert "<weird>" not in unknown and "sev-info" in unknown


def test_no_inline_styles_because_streamlit_strips_them():
    html = c.events_table([parsed()]) + c.kpi_card("x", 1, "y", "high") + c.health_pills(None)
    assert "style=" not in html


def test_every_severity_has_a_css_rule():
    sheet = css()
    for name, colour in SEVERITY_COLOURS.items():
        assert f".sev-{name}{{--c:{colour};}}" in sheet


def test_health_pills_cover_the_four_states():
    ready = Health.model_validate({"status": "ready", "api": {"status": "up"}, "database": {"status": "up", "latency_ms": 1.0}})
    down = Health.model_validate({"status": "not_ready", "api": {"status": "up"}, "database": {"status": "down"}})
    assert "API healthy" in c.health_pills(ready) and "Database healthy" in c.health_pills(ready)
    assert "Database unavailable" in c.health_pills(down) and "API healthy" in c.health_pills(down)
    assert "API unavailable" in c.health_pills(None) and "Database unknown" in c.health_pills(None)


def test_times_are_utc_and_labelled():
    ist = timezone(timedelta(hours=5, minutes=30))
    assert c.fmt_time(datetime(2026, 11, 7, 10, 0, tzinfo=ist)) == "07 Nov 2026 04:30 UTC"
    assert c.fmt_time_short(datetime(2026, 11, 7, 10, 0, tzinfo=ist)) == "07 Nov 04:30"


def test_primary_indicator_order_and_long_values_are_shortened():
    assert c.primary_indicator(parsed(source_ip="1.2.3.4", domain="x.example")) == ("IP", "1.2.3.4")
    assert c.primary_indicator(parsed(file_hash="a" * 64)) == ("SHA-256", "a" * 64)
    assert c.primary_indicator(parsed()) == ("", "")
    assert "…" in c.events_table([parsed(file_hash="a" * 64)]) and "a" * 64 not in c.events_table([parsed(file_hash="a" * 64)])


def test_tables_with_no_rows_still_render_headers():
    assert "<th" in c.events_table([]) and "<th" in c.indicators_table([])


def test_score_is_always_next_to_the_experimental_label_in_the_overview_notes():
    from ts_dashboard.theme import SCORE_NOTE
    assert "not a probability of compromise" in SCORE_NOTE and SCORE_NOTE.startswith("Experimental prioritisation score")


def test_loading_skeletons_carry_no_inline_style():
    assert "style=" not in c.kpi_skeletons() and c.kpi_skeletons(3).count("ts-skeleton") == 3


def test_times_far_outside_the_usual_range_format_without_raising():
    assert c.fmt_time(datetime(1, 1, 1, tzinfo=timezone.utc)).endswith("UTC")
    assert "9999" in c.fmt_time(datetime(9999, 6, 1, tzinfo=timezone.utc))
    assert c.fmt_time_short(datetime(1, 1, 1, tzinfo=timezone.utc)).endswith(":00")


# ---- credentials inside URLs are never displayed --------------------------------------------------

CRED_URL = "http://admin:hunter2@evil.test/x"
LEAKY_EVENT = dict(url=CRED_URL, description=f"fetched {CRED_URL}", indicators=[indicator(1, "url", CRED_URL, sightings=2)])


def _leaky_event() -> Event:
    return parsed(**LEAKY_EVENT)


def _incident_detail() -> str:
    from ts_dashboard.models import Incident
    from tests.fake_backend import incident
    return c.incident_detail(Incident.model_validate({**incident(1), "summary": f"see {CRED_URL}"}))


def _graph() -> str:
    clusters = co.correlate([_leaky_event(), parsed(**LEAKY_EVENT)])
    graph = co.build_graph(clusters[0], clusters)
    return " ".join(n.label + n.hover for n in graph.nodes)


def _default_title() -> str:
    from ts_dashboard.incidents import default_title
    return default_title("url", CRED_URL)


@pytest.mark.parametrize("render", [
    lambda: c.events_table([_leaky_event()]),
    lambda: c.high_risk_table([_leaky_event()]),
    lambda: c.event_detail(_leaky_event()),
    lambda: c.indicators_table(_leaky_event().indicators),
    lambda: c.event_indicators_table(_leaky_event()),
    lambda: c.indicators_full_table(_leaky_event().indicators),
    lambda: c.indicator_detail(_leaky_event().indicators[0]),
    lambda: c.clusters_table(co.correlate([_leaky_event(), _leaky_event()])),
    _incident_detail,
    _graph,
    _default_title,
], ids=["events_table", "high_risk_table", "event_detail", "indicators_table", "event_indicators_table",
        "indicators_full_table", "indicator_detail", "clusters_table", "incident_detail", "graph", "default_title"])
def test_credentials_in_urls_are_hidden_everywhere(render):
    out = render()
    assert "hunter2" not in out and "admin:" not in out and "[redacted]" in out


def test_credentials_are_hidden_before_long_values_are_shortened():
    # the '@' is past every cut limit, so shortening first would leave "admin:ppppp..." behind
    long_url = "http://admin:" + "p" * 60 + "@host/x"
    html = c.events_table([parsed(url=long_url)]) + c.high_risk_table([parsed(url=long_url)])
    assert "admin:" not in html and "ppppp" not in html and "[redacted]" in html


def test_small_share_shows_less_than_one_percent():
    assert c.percent(1, 1000) == "<1%" and c.percent(4, 1000) == "<1%"
    assert c.percent(0, 1000) == "0%" and c.percent(6, 1000) == "1%" and c.percent(1, 2) == "50%" and c.percent(7, 7) == "100%"
