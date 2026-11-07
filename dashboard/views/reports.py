"""Reports: summaries of stored data, CSV export of events, downloadable investigation summaries."""
from datetime import datetime, timezone

import streamlit as st

from ts_dashboard import charts, components
from ts_dashboard.api_client import ApiError, ThreatScopeApi
from ts_dashboard.events import CUSTOM_RANGE, RANGE_PRESETS, EventFilters, time_range
from ts_dashboard.models import SEVERITIES, SOURCES
from ts_dashboard.reports import (
    EXPORT_MAX, build_report, describe_scope, events_to_csv, fetch_export, incident_markdown, report_markdown,
)
from ts_dashboard.theme import INDICATOR_LABELS, SCORE_NOTE, SEVERITY_LABELS, SOURCE_LABELS
from views.common import page_header, require_api

FILTER_KEYS = ("rp_range", "rp_from", "rp_to", "rp_source", "rp_severity")


def _clear() -> None:
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)
    st.session_state.pop("rp_csv", None)


def _scope() -> tuple[EventFilters | None, str]:
    with st.container(key="panel-rp-scope"):
        a, b, c, d = st.columns([2, 2, 2, 1.5], vertical_alignment="bottom")
        preset = a.selectbox("Time range (UTC)", [*RANGE_PRESETS, CUSTOM_RANGE], key="rp_range")
        source = b.selectbox("Source", [None, *SOURCES], key="rp_source", format_func=lambda v: "All sources" if v is None else SOURCE_LABELS[v])
        severity = c.selectbox("Severity", [None, *SEVERITIES[::-1]], key="rp_severity",
                               format_func=lambda v: "All severities" if v is None else SEVERITY_LABELS[v])
        d.button("Clear filters", icon=":material/filter_alt_off:", on_click=_clear, use_container_width=True)
        start_date = end_date = None
        if preset == CUSTOM_RANGE:
            e, f = st.columns(2)
            start_date = e.date_input("From (UTC date)", value=None, key="rp_from")
            end_date = f.date_input("To (UTC date, included)", value=None, key="rp_to")
    if start_date and end_date and start_date > end_date:
        return None, "The From date is after the To date."
    start, end = time_range(preset, datetime.now(timezone.utc), start_date, end_date)
    return EventFilters(source=source, severity=severity, start_time=start, end_time=end), ""


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%d-%H%M")


def _exports(api: ThreatScopeApi, report, scope: EventFilters) -> None:
    with st.container(key="panel-rp-export"):
        st.markdown(components.panel_heading("Export", "Downloads are generated from the data above, read through the API just now"),
                    unsafe_allow_html=True)
        st.download_button("Download summary report (Markdown)", report_markdown(report), file_name=f"threatscope-report-{_stamp(report.generated_at)}.md",
                           mime="text/markdown", icon=":material/description:", key="rp_dl_report")
        st.write("")
        signature = (scope, EXPORT_MAX)
        if st.button(f"Prepare events CSV (up to {EXPORT_MAX:,} newest)", icon=":material/table_view:", key="rp_prepare"):
            try:
                events, total = fetch_export(api, scope)
            except ApiError as error:
                st.markdown(components.error_state("The export could not be prepared", error.user_message), unsafe_allow_html=True)
            else:
                st.session_state["rp_csv"] = {"sig": signature, "data": events_to_csv(events), "rows": len(events), "total": total,
                                              "at": datetime.now(timezone.utc)}
        prepared = st.session_state.get("rp_csv")
        if prepared and prepared["sig"] == signature:
            note = f"{prepared['rows']:,} of {prepared['total']:,} events in scope"
            if prepared["rows"] < prepared["total"]:
                note += f" (the newest {EXPORT_MAX:,}; narrow the time range to export the rest)"
            st.markdown(components.note(f"Ready: {note}. Prepared {prepared['at']:%H:%M:%S} UTC. Descriptions, URLs and metadata have secrets hidden, "
                                        "and cells that start like spreadsheet formulas are neutralised."), unsafe_allow_html=True)
            st.download_button("Download events CSV", prepared["data"], file_name=f"threatscope-events-{_stamp(prepared['at'])}.csv",
                               mime="text/csv", icon=":material/download:", key="rp_dl_csv")
        elif prepared:
            st.markdown(components.note("The filters changed since the CSV was prepared. Prepare it again."), unsafe_allow_html=True)
        st.write("")
        _incident_summary(api)


def _incident_summary(api: ThreatScopeApi) -> None:
    try:
        incidents = api.list_incidents(limit=100).items
    except ApiError as error:
        st.markdown(components.error_state("Incidents could not be loaded", error.user_message), unsafe_allow_html=True)
        return
    if not incidents:
        st.markdown(components.note("No incidents exist yet, so there is no investigation summary to download."), unsafe_allow_html=True)
        return
    by_id = {i.id: i for i in incidents}
    chosen = st.selectbox("Investigation summary for an incident", list(by_id), key="rp_incident",
                          format_func=lambda v: f"#{v} · {by_id[v].title[:70]} · {by_id[v].status}")
    try:
        detail = api.get_incident(chosen)
    except ApiError as error:
        st.markdown(components.error_state("The incident could not be loaded", error.user_message), unsafe_allow_html=True)
        return
    st.download_button("Download incident summary (Markdown)", incident_markdown(detail), file_name=f"threatscope-incident-{detail.id}.md",
                       mime="text/markdown", icon=":material/assignment:", key="rp_dl_incident")


def render() -> None:
    api = require_api()
    page_header("Reports", "Summaries of stored data, with CSV and Markdown exports", api)
    scope, problem = _scope()
    st.write("")
    if scope is None:
        st.markdown(components.empty_state("That range cannot be reported", problem), unsafe_allow_html=True)
        return
    try:
        report = build_report(api, scope)
    except ApiError as error:
        st.markdown(components.error_state("The report is unavailable", error.user_message + " Use Refresh to try again."), unsafe_allow_html=True)
        return

    high = report.by_severity["critical"] + report.by_severity["high"]
    cards = [components.kpi_card("Events in scope", report.total, describe_scope(scope)),
             components.kpi_card("Critical or high", high, f"{high / report.total:.0%} of events in scope" if report.total else "no events in scope",
                                 "critical" if report.by_severity["critical"] else ("high" if report.by_severity["high"] else None)),
             components.kpi_card("Sources reporting", sum(1 for n in report.by_source.values() if n), f"of {len(report.by_source)} sources"),
             components.kpi_card("Recurring indicators", len(report.recurring), "in 2+ events of this scope")]
    for column, card in zip(st.columns(4), cards):
        column.markdown(card, unsafe_allow_html=True)
    st.write("")

    if not report.total:
        with st.container(key="panel-rp-empty"):
            st.markdown(components.empty_state("No events in this scope", "Widen the time range or clear the filters. "
                                               "Reports only summarise events that are stored."), unsafe_allow_html=True)
        return

    left, right = st.columns(2)
    with left.container(key="panel-rp-severity"):
        st.markdown(components.panel_heading("Severity distribution", "Exact counts for the scope above"), unsafe_allow_html=True)
        st.plotly_chart(charts.severity_figure(report.by_severity), use_container_width=True, config=charts.CHART_CONFIG, theme=None)
    with right.container(key="panel-rp-source"):
        st.markdown(components.panel_heading("Events by source", "Exact counts for the scope above"), unsafe_allow_html=True)
        st.plotly_chart(charts.source_figure(report.by_source), use_container_width=True, config=charts.CHART_CONFIG, theme=None)

    sampled = f"the newest {report.analysed:,} of {report.total:,} events in scope" if report.truncated else "all events in scope"
    with st.container(key="panel-rp-types"):
        st.markdown(components.panel_heading("Most frequent event types", f"Computed from {sampled}"), unsafe_allow_html=True)
        st.markdown(components.table([("Event type", False), ("Events", True)],
                                     [[components.cell_mono(t), f"<strong>{n}</strong>"] for t, n in report.event_types]), unsafe_allow_html=True)
    with st.container(key="panel-rp-high"):
        st.markdown(components.panel_heading("High-risk events", "Critical and high severity, highest experimental risk score first"), unsafe_allow_html=True)
        if report.high_risk:
            st.markdown(components.events_table(report.high_risk, with_id=True) + components.note(SCORE_NOTE), unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("No high-risk events", "No critical or high severity event is in this scope."), unsafe_allow_html=True)
    with st.container(key="panel-rp-recurring"):
        st.markdown(components.panel_heading("Top recurring indicators", f"Indicators in 2+ events, from {sampled}"), unsafe_allow_html=True)
        if report.recurring:
            rows = [[components.cell_nowrap(INDICATOR_LABELS.get(r.indicator.type, r.indicator.type)), components.cell_mono(r.indicator.value, 70),
                     f"<strong>{r.events_in_scope}</strong>", f"{r.indicator.sighting_count}"] for r in report.recurring]
            st.markdown(components.table([("Type", False), ("Value", False), ("Events in scope", True), ("Sightings (all time)", True)], rows)
                        + components.note("A recurring indicator is a lead to investigate, not proof of malicious activity."), unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("Nothing recurring", "No indicator appears in more than one event of this scope."), unsafe_allow_html=True)
    with st.container(key="panel-rp-incidents"):
        c = report.incidents
        st.markdown(components.panel_heading("Incidents", "All stored incidents (not limited by the filters above)"), unsafe_allow_html=True)
        st.markdown(components.table([("Open", True), ("Investigating", True), ("Closed", True), ("Total", True)],
                                     [[f"<strong>{c['open']}</strong>", f"<strong>{c['investigating']}</strong>", f"<strong>{c['closed']}</strong>",
                                       f"<strong>{c['all']}</strong>"]]), unsafe_allow_html=True)
    st.write("")
    _exports(api, report, scope)
