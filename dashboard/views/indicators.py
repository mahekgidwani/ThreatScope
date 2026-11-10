"""Indicator Explorer: IPs, domains, URLs and SHA-256 hashes the backend extracted from events."""
import streamlit as st

from ts_dashboard import components
from ts_dashboard.api_client import ApiError, ThreatScopeApi
from ts_dashboard.correlation import events_with_indicator, scan_events
from ts_dashboard.indicators import PAGE_SIZES, SORT_SCAN, SORTS, fetch_indicator_page
from ts_dashboard.models import INDICATOR_TYPES, Indicator
from ts_dashboard.redact import redact
from ts_dashboard.theme import INDICATOR_LABELS
from views.common import page_header, require_api

FILTER_KEYS = ("ix_type", "ix_value", "ix_sort", "ix_size")
CAUTION = "An indicator is something observed in an event. Its presence is a lead to investigate, not proof that it is malicious."
TIMES = "Recorded = when ThreatScope stored the event that mentioned it. This can be later than when the event occurred."


def _clear() -> None:
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)
    st.session_state["ix_page"] = 0


def _set_page(delta: int) -> None:
    st.session_state["ix_page"] = max(0, st.session_state.get("ix_page", 0) + delta)


def _detail(api: ThreatScopeApi, indicator: Indicator) -> None:
    with st.container(key="panel-ix-detail"):
        st.markdown(components.panel_heading("Indicator details", CAUTION), unsafe_allow_html=True)
        st.markdown(components.indicator_detail(indicator), unsafe_allow_html=True)
        st.write("")
        try:
            scan = scan_events(api)
        except ApiError as error:
            st.markdown(components.error_state("Related events could not be loaded", error.user_message), unsafe_allow_html=True)
            return
        related = events_with_indicator(scan.events, indicator.id)
        sub = "Events that mention this indicator"
        if scan.truncated:
            sub += f" · searched the newest {len(scan.events):,} of {scan.total:,} events"
        st.markdown(components.panel_heading("Related events", sub), unsafe_allow_html=True)
        if related:
            st.markdown(components.events_table(related[:50], with_id=True)
                        + (components.note(f"Showing 50 of {len(related)}.") if len(related) > 50 else ""), unsafe_allow_html=True)
            sources = sorted({e.source for e in related})
            st.markdown(components.note(f"{len(related)} events from {len(sources)} source(s): {', '.join(sources)}. "
                                        "Open the Events page and search an event ID for full details."), unsafe_allow_html=True)
        else:
            st.markdown(components.empty_state("No related events found", "None of the events searched mention this indicator."),
                        unsafe_allow_html=True)


def render() -> None:
    api = require_api()
    page_header("Indicators", "IP addresses, domains, URLs and file hashes seen in events", api)
    with st.container(key="panel-ix-filters"):
        a, b, c, d = st.columns([2, 4, 2, 1.5], vertical_alignment="bottom")
        indicator_type = a.selectbox("Type", [None, *INDICATOR_TYPES], key="ix_type",
                                     format_func=lambda v: "Any type" if v is None else INDICATOR_LABELS[v])
        value = b.text_input("Value (exact match)", key="ix_value", placeholder="IP, domain, URL or SHA-256")
        sort = c.selectbox("Sort", SORTS, key="ix_sort")
        size = d.selectbox("Rows per page", PAGE_SIZES, index=1, key="ix_size")
        st.button("Clear filters", icon=":material/filter_alt_off:", on_click=_clear)
    st.write("")

    signature = (indicator_type, (value or "").strip(), sort, size)
    if st.session_state.get("ix_sig") != signature:
        st.session_state["ix_sig"], st.session_state["ix_page"] = signature, 0
    try:
        result = fetch_indicator_page(api, indicator_type, value, st.session_state.get("ix_page", 0), size, sort)
    except ApiError as error:
        st.markdown(components.error_state("Indicators are unavailable", error.user_message + " Use Refresh to try again."),
                    unsafe_allow_html=True)
        return
    st.session_state["ix_page"] = result.page

    with st.container(key="panel-indicators-list"):
        sub = f"{result.total:,} match · {sort.lower()}"
        if result.sorted_over:
            sub += f" · sorted within the first {result.sorted_over:,} of {result.total:,}"
        st.markdown(components.panel_heading("Indicators", sub), unsafe_allow_html=True)
        if not result.items:
            filtered = bool(indicator_type or signature[1])
            st.markdown(components.empty_state("No indicators match" if filtered else "No indicators yet",
                                               "Change or clear the filters." if filtered else
                                               "Indicators appear when stored events contain an IP, domain, URL or file hash."),
                        unsafe_allow_html=True)
            return
        st.markdown(components.indicators_full_table(result.items), unsafe_allow_html=True)
        prev, label, nxt = st.columns([1, 3, 1], vertical_alignment="center")
        prev.button("Previous", icon=":material/chevron_left:", disabled=result.page == 0, on_click=_set_page, args=(-1,),
                    key="ix_prev", use_container_width=True)
        label.markdown(f'<div class="ts-note ts-center">Showing {result.first_item:,}–{result.last_item:,} of {result.total:,} · '
                       f'page {result.page + 1} of {result.pages}</div>', unsafe_allow_html=True)
        nxt.button("Next", icon=":material/chevron_right:", disabled=result.page + 1 >= result.pages, on_click=_set_page,
                   args=(1,), key="ix_next", use_container_width=True)
        by_id = {i.id: i for i in result.items}
        picked = st.selectbox("Inspect an indicator", [None, *by_id], key=f"ix_pick-{hash(signature)}-{result.page}",
                              format_func=lambda v: "Choose an indicator on this page…" if v is None else
                              f"{INDICATOR_LABELS[by_id[v].type]} · {redact(by_id[v].value)[:60]}")
        st.markdown(components.note(CAUTION + " " + TIMES), unsafe_allow_html=True)
    if picked:
        _detail(api, by_id[picked])
