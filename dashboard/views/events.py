"""Events Explorer: filter, page through and inspect stored events."""
from datetime import datetime, timezone

import streamlit as st

from ts_dashboard import components
from ts_dashboard.api_client import ApiError, ThreatScopeApi
from ts_dashboard.events import (
    CUSTOM_RANGE, PAGE_SIZES, RANGE_PRESETS, EventFilters, classify_search, event_type_options,
    fetch_event_page, related_events, time_range,
)
from ts_dashboard.models import SEVERITIES, SOURCES, Event
from ts_dashboard.redact import redact
from ts_dashboard.theme import SCORE_NOTE, SEVERITY_LABELS, SOURCE_LABELS
from views.common import page_header, require_api

FILTER_KEYS = ("ev_search", "ev_source", "ev_severity", "ev_type", "ev_range", "ev_from", "ev_to", "ev_sort", "ev_size")
SORTS = {"Newest first": False, "Oldest first": True}


def _clear_filters() -> None:
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)
    st.session_state["ev_page"] = 0


def _set_page(delta: int) -> None:
    st.session_state["ev_page"] = max(0, st.session_state.get("ev_page", 0) + delta)


def _filter_area(api: ThreatScopeApi) -> tuple[EventFilters | None, str, bool, int, object]:
    """Draw the filters. Returns (filters, message, ascending, page_size, search) where `filters` is None when the
    inputs cannot be turned into a query (the message says why)."""
    with st.container(key="panel-filters"):
        st.text_input("Search", key="ev_search", placeholder="Event ID, source IP address or domain (exact match)",
                      help="The API can look up an event by ID and filter by exact source IP or exact domain.")
        a, b, c, d = st.columns(4)
        source = a.selectbox("Source", [None, *SOURCES], key="ev_source",
                             format_func=lambda v: "Any source" if v is None else SOURCE_LABELS[v])
        severity = b.selectbox("Severity", [None, *SEVERITIES[::-1]], key="ev_severity",
                               format_func=lambda v: "Any severity" if v is None else SEVERITY_LABELS[v])
        try:
            types = event_type_options(api)
        except ApiError:
            types = []
        event_type = c.selectbox("Event type", [None, *types], key="ev_type",
                                 format_func=lambda v: "Any type" if v is None else v,
                                 help="Types seen in the newest 500 events.")
        preset = d.selectbox("Time range (UTC)", [*RANGE_PRESETS, CUSTOM_RANGE], key="ev_range")
        start_date = end_date = None
        if preset == CUSTOM_RANGE:
            e, f = st.columns(2)
            start_date = e.date_input("From (UTC date)", value=None, key="ev_from")
            end_date = f.date_input("To (UTC date, included)", value=None, key="ev_to")
        g, h, i = st.columns([2, 2, 1], vertical_alignment="bottom")
        ascending = SORTS[g.selectbox("Sort by occurrence time", list(SORTS), key="ev_sort")]
        page_size = h.selectbox("Rows per page", PAGE_SIZES, index=1, key="ev_size")
        i.button("Clear filters", icon=":material/filter_alt_off:", on_click=_clear_filters, use_container_width=True)

    search = classify_search(st.session_state.get("ev_search", ""))
    if search.kind == "unsupported":
        return None, search.message, ascending, page_size, search
    if start_date and end_date and start_date > end_date:
        return None, "The From date is after the To date.", ascending, page_size, search
    start, end = time_range(preset, datetime.now(timezone.utc), start_date, end_date)
    filters = EventFilters(source=source, severity=severity, event_type=event_type, start_time=start, end_time=end,
                           source_ip=search.value if search.kind == "ip" else None,
                           domain=search.value if search.kind == "domain" else None)
    return filters, "", ascending, page_size, search


def _detail(api: ThreatScopeApi, event_id: str) -> None:
    with st.container(key="panel-detail"):
        try:
            event = api.get_event(event_id)
        except ApiError as error:
            st.markdown(components.error_state("Event could not be loaded", error.user_message), unsafe_allow_html=True)
            return
        st.markdown(components.panel_heading("Event details", "Read from the API just now. Metadata is shown with secrets hidden."),
                    unsafe_allow_html=True)
        left, right = st.columns([3, 2])
        with left:
            st.markdown(components.event_detail(event), unsafe_allow_html=True)
        with right:
            st.markdown(components.panel_heading("Risk score", SCORE_NOTE), unsafe_allow_html=True)
            st.markdown(components.risk_factors_table(event), unsafe_allow_html=True)
        st.write("")
        st.markdown(components.panel_heading("Indicators in this event", "From the event's own fields"), unsafe_allow_html=True)
        st.markdown(components.event_indicators_table(event), unsafe_allow_html=True)
        st.markdown(components.panel_heading("Metadata", "Raw detector output, secrets hidden"), unsafe_allow_html=True)
        if event.metadata:
            st.json(redact(event.metadata), expanded=1)
        else:
            st.markdown(components.empty_state("No metadata", "This event carries no extra detector output."), unsafe_allow_html=True)
        _related(api, event)


def _related(api: ThreatScopeApi, event: Event) -> None:
    st.markdown(components.panel_heading("Related events", "Other events with the same source IP or domain"), unsafe_allow_html=True)
    try:
        groups = related_events(api, event)
    except ApiError as error:
        st.markdown(components.error_state("Related events could not be loaded", error.user_message), unsafe_allow_html=True)
        return
    if not groups:
        st.markdown(components.empty_state("Nothing to match on", "This event has no source IP or domain. Events sharing only a URL or "
                                           "file hash cannot be listed yet: the API has no filter for them."), unsafe_allow_html=True)
        return
    for label, others in groups.items():
        if others:
            st.markdown(components.note(f"Also seen with {label}:") + components.high_risk_table(others), unsafe_allow_html=True)
        else:
            st.markdown(components.note(f"No other events share {label}."), unsafe_allow_html=True)


def render() -> None:
    api = require_api()
    page_header("Events", "Search, filter and inspect every collected event", api)
    filters, message, ascending, page_size, search = _filter_area(api)
    st.write("")

    if filters is None:
        st.markdown(components.empty_state("That search cannot be run", message), unsafe_allow_html=True)
        return
    if search.kind == "event_id":
        _detail(api, search.value)
        return

    signature = (filters, ascending, page_size)
    if st.session_state.get("ev_sig") != signature:
        st.session_state["ev_sig"], st.session_state["ev_page"] = signature, 0
    try:
        result = fetch_event_page(api, filters, st.session_state.get("ev_page", 0), page_size, ascending)
    except ApiError as error:
        st.markdown(components.error_state("Events are unavailable", error.user_message + " Use Refresh to try again."),
                    unsafe_allow_html=True)
        return
    st.session_state["ev_page"] = result.page

    with st.container(key="panel-events"):
        order = "oldest first" if ascending else "newest first"
        st.markdown(components.panel_heading("Events", f"{result.total:,} match · {order} by occurrence time (UTC)"), unsafe_allow_html=True)
        if not result.items:
            title, text = (("No events match", "Change or clear the filters.") if filters.active
                           else ("No events yet", "Run an adapter to collect some (see docs/INTEGRATIONS.md)."))
            st.markdown(components.empty_state(title, text), unsafe_allow_html=True)
            return
        st.markdown(components.events_table(result.items, with_id=True), unsafe_allow_html=True)
        previous, label, following = st.columns([1, 3, 1], vertical_alignment="center")
        previous.button("Previous", icon=":material/chevron_left:", disabled=result.page == 0, on_click=_set_page, args=(-1,),
                        key="ev_prev", use_container_width=True)
        label.markdown(f'<div class="ts-note ts-center">Showing {result.first_item:,}–{result.last_item:,} of '
                       f'{result.total:,} · page {result.page + 1} of {result.pages}</div>', unsafe_allow_html=True)
        following.button("Next", icon=":material/chevron_right:", disabled=result.page + 1 >= result.pages, on_click=_set_page,
                         args=(1,), key="ev_next", use_container_width=True)
        st.markdown(components.note(SCORE_NOTE), unsafe_allow_html=True)
        by_id = {str(e.id): e for e in result.items}
        picked = st.selectbox(
            "Inspect an event", [None, *by_id], key=f"ev_pick-{hash(signature)}-{result.page}",
            format_func=lambda v: "Choose an event on this page…" if v is None else
            f"{components.fmt_time(by_id[v].occurred_at)} · {SEVERITY_LABELS[by_id[v].severity]} · {by_id[v].event_type} · {v[:8]}")
    if picked:
        _detail(api, picked)
