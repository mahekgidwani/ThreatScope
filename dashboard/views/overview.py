"""Overview page: KPIs, three charts, recent events, recurring indicators, recent high-risk activity."""
import streamlit as st

from ts_dashboard import charts, components
from ts_dashboard.api_client import ApiError
from ts_dashboard.overview import Overview, load_overview
from ts_dashboard.theme import SCORE_NOTE
from views.common import page_header, require_api

STEP_NAMES = {3600: "hour", 21600: "6 hours", 86400: "day", 604800: "week", 2592000: "30 days"}
NO_EVENTS_HINT = ("Run an adapter to collect some, for example: python -m integrations.analyse_file PATH "
                  "(see docs/INTEGRATIONS.md).")


def _percent(part: int, whole: int) -> str:
    return f"{part / whole:.0%} of all events" if whole else "no events yet"


def _kpis(data: Overview) -> None:
    sources_reporting = sum(1 for n in data.by_source.values() if n)
    plus = "+" if data.indicators_truncated else ""
    cards = [
        components.kpi_card("Total events", data.total_events,
                            f"from {sources_reporting} of {len(data.by_source)} sources" if data.total_events else "no events yet"),
        components.kpi_card("Critical events", data.by_severity["critical"], _percent(data.by_severity["critical"], data.total_events),
                            "critical"),
        components.kpi_card("High-risk events", data.by_severity["high"], _percent(data.by_severity["high"], data.total_events),
                            "high"),
        components.kpi_card("Total indicators", data.total_indicators,
                            f"{data.repeated_indicators}{plus} recurring" if data.total_indicators else "none extracted yet"),
        components.kpi_card("Open incidents", data.open_incidents, f"of {data.total_incidents} incidents"),
    ]
    for column, card in zip(st.columns(5), cards):
        column.markdown(card, unsafe_allow_html=True)


def _charts(data: Overview) -> None:
    wide, mid, narrow = st.columns([2, 1, 1])
    with wide.container(key="panel-trend"):
        if data.trend is None:
            st.markdown(components.panel_heading("Events over time", "By occurrence time, split by severity"), unsafe_allow_html=True)
            st.markdown(components.empty_state("No events to plot", NO_EVENTS_HINT), unsafe_allow_html=True)
        else:
            size = STEP_NAMES.get(int(data.trend.step.total_seconds()), "bucket")
            sub = f"One bar per {size}, by occurrence time (UTC), split by severity"
            if data.trend_truncated:
                sub += f" · newest {data.trend_events_used:,} of {data.total_events:,} events"
            st.markdown(components.panel_heading("Events over time", sub), unsafe_allow_html=True)
            st.plotly_chart(charts.trend_figure(data.trend), use_container_width=True, config=charts.CHART_CONFIG, theme=None)
    for column, key, title, sub, figure, counts in (
            (mid, "panel-severity", "Events by severity", "All stored events", charts.severity_figure, data.by_severity),
            (narrow, "panel-source", "Events by source", "All stored events", charts.source_figure, data.by_source)):
        with column.container(key=key):
            st.markdown(components.panel_heading(title, sub), unsafe_allow_html=True)
            if data.total_events:
                st.plotly_chart(figure(counts), use_container_width=True, config=charts.CHART_CONFIG, theme=None)
            else:
                st.markdown(components.empty_state("No events yet", NO_EVENTS_HINT), unsafe_allow_html=True)


def _tables(data: Overview) -> None:
    with st.container(key="panel-recent"):
        st.markdown(components.panel_heading("Recent security events", "Newest 10 by occurrence time (UTC)"), unsafe_allow_html=True)
        if data.recent_events:
            st.markdown(components.events_table(data.recent_events) + components.note(SCORE_NOTE), unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("No events yet", NO_EVENTS_HINT), unsafe_allow_html=True)
    left, right = st.columns(2)
    with left.container(key="panel-indicators"):
        sub = "Seen more than once"
        if data.indicators_truncated:
            sub += f" · among the {data.indicators_scanned:,} most recently seen of {data.total_indicators:,}"
        st.markdown(components.panel_heading("Top recurring indicators", sub), unsafe_allow_html=True)
        if data.top_indicators:
            st.markdown(components.indicators_table(data.top_indicators)
                        + components.note("A recurring indicator is a lead to investigate, not proof of malicious activity."),
                        unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("Nothing recurring yet", "No indicator has been seen more than once."),
                        unsafe_allow_html=True)
    with right.container(key="panel-highrisk"):
        st.markdown(components.panel_heading("Recent high-risk activity", "Newest critical and high severity events"), unsafe_allow_html=True)
        if data.high_risk:
            st.markdown(components.high_risk_table(data.high_risk) + components.note(SCORE_NOTE), unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("No high-risk events", "No stored event has critical or high severity."),
                        unsafe_allow_html=True)


def render() -> None:
    api = require_api()
    page_header("Overview", "Current state of the events ThreatScope has collected", api)
    placeholder = st.empty()
    placeholder.markdown(components.kpi_skeletons(), unsafe_allow_html=True)
    try:
        data = load_overview(api)
    except ApiError as error:
        placeholder.empty()
        st.markdown(components.error_state("Overview data is unavailable", error.user_message
                                           + " Use Refresh to try again."), unsafe_allow_html=True)
        return
    placeholder.empty()
    _kpis(data)
    st.write("")
    _charts(data)
    st.write("")
    _tables(data)
