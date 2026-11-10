"""Correlation: indicators shared by several events, and the events they connect."""
import streamlit as st

from ts_dashboard import charts, components
from ts_dashboard.api_client import ApiError
from ts_dashboard.correlation import build_graph, correlate, scan_events
from ts_dashboard.models import INDICATOR_TYPES
from ts_dashboard.redact import redact
from ts_dashboard.theme import INDICATOR_LABELS
from views.common import page_header, require_api

EVIDENCE = ("A shared indicator means the same value was observed in several stored events. "
            "It is a lead to investigate, not proof that one actor is behind them.")


def render() -> None:
    api = require_api()
    page_header("Correlation", "Events that share indicators", api)
    try:
        scan = scan_events(api)
    except ApiError as error:
        st.markdown(components.error_state("Correlation data is unavailable", error.user_message + " Use Refresh to try again."),
                    unsafe_allow_html=True)
        return

    with st.container(key="panel-co-filters"):
        a, b, c = st.columns([2, 2, 3], vertical_alignment="bottom")
        indicator_type = a.selectbox("Indicator type", [None, *INDICATOR_TYPES], key="co_type",
                                     format_func=lambda v: "Any type" if v is None else INDICATOR_LABELS[v])
        minimum = b.number_input("Minimum events", min_value=2, max_value=50, value=2, step=1, key="co_min")
        cross_only = c.checkbox("Only indicators seen in more than one source", key="co_cross")
    st.write("")

    everything = correlate(scan.events)
    clusters = correlate(scan.events, int(minimum), indicator_type, cross_only)
    involved = {e.id for k in clusters for e in k.events}
    cards = [components.kpi_card("Shared indicators", len(clusters), "found in 2 or more events" if minimum == 2 else f"found in {int(minimum)}+ events"),
             components.kpi_card("Cross-source", sum(1 for k in clusters if k.cross_source), "seen by more than one source"),
             components.kpi_card("Events involved", len(involved), f"of {len(scan.events):,} searched")]
    for column, card in zip(st.columns(3), cards):
        column.markdown(card, unsafe_allow_html=True)
    st.write("")

    with st.container(key="panel-co-list"):
        sub = "Strongest first: seen by several sources, then most events, then highest risk score"
        if scan.truncated:
            sub += f" · searched the newest {len(scan.events):,} of {scan.total:,} events"
        st.markdown(components.panel_heading("Shared indicators", sub), unsafe_allow_html=True)
        if not clusters:
            filtered = indicator_type or cross_only or minimum > 2
            title, text = (("No shared indicators match", "Relax the filters.") if filtered and everything else
                           ("No shared indicators yet", "No indicator appears in more than one event. Correlation needs events that "
                            "mention the same IP, domain, URL or file hash.") if scan.events else
                           ("No events yet", "Run an adapter to collect some (see docs/INTEGRATIONS.md)."))
            st.markdown(components.empty_state(title, text), unsafe_allow_html=True)
            return
        shown = clusters[:50]
        st.markdown(components.clusters_table(shown)
                    + components.note(EVIDENCE + (f" Showing the first 50 of {len(clusters)}." if len(clusters) > 50 else "")),
                    unsafe_allow_html=True)
        by_id = {k.indicator.id: k for k in shown}
        picked = st.selectbox("Inspect a shared indicator", list(by_id), key=f"co_pick-{indicator_type}-{minimum}-{cross_only}",
                              format_func=lambda v: f"{INDICATOR_LABELS[by_id[v].indicator.type]} · {redact(by_id[v].indicator.value)[:60]} "
                                                    f"· {by_id[v].count} events")
    chosen = by_id[picked]

    with st.container(key="panel-co-graph"):
        st.markdown(components.panel_heading("Relationship graph", "Diamonds are shared indicators, circles are events coloured by severity. "
                                             "A line means the event mentions the indicator."), unsafe_allow_html=True)
        graph = build_graph(chosen, everything)
        st.plotly_chart(charts.graph_figure(graph), use_container_width=True, config=charts.CHART_CONFIG, theme=None)
        if graph.events_shown < graph.events_total:
            st.markdown(components.note(f"Showing the newest {graph.events_shown} of {graph.events_total} events."), unsafe_allow_html=True)

    with st.container(key="panel-co-events"):
        st.markdown(components.panel_heading(f"Events sharing {redact(chosen.indicator.value)[:60]}",
                                             f"{chosen.count} events from {len(chosen.sources)} source(s) · risk scores are experimental"),
                    unsafe_allow_html=True)
        st.markdown(components.events_table(chosen.events[:100], with_id=True) + components.note(
            "Experimental prioritisation score — not a probability of compromise."), unsafe_allow_html=True)
        st.caption("Event IDs (copy to search on the Events page)")
        st.code("\n".join(str(e.id) for e in chosen.events), language=None)
