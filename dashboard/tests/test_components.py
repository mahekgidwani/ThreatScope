from datetime import datetime, timedelta, timezone

import pytest

from tests.fake_backend import T0, event, indicator
from ts_dashboard import components as c
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
