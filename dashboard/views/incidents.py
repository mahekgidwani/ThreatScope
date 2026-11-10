"""Incident Management: see incidents, inspect their events, group related events, track the investigation."""
import streamlit as st

from ts_dashboard import components
from ts_dashboard.api_client import ApiError, ApiWriteDisabledError, ThreatScopeApi
from ts_dashboard.correlation import correlate, scan_events
from ts_dashboard.incidents import (
    MAX_EVENT_IDS, PAGE_SIZES, STATUS_LABELS, default_title, fetch_incident_page, parse_event_ids, status_counts,
)
from ts_dashboard.models import INCIDENT_STATUSES
from ts_dashboard.redact import redact
from ts_dashboard.theme import INDICATOR_LABELS, SCORE_NOTE
from views.common import page_header, require_api

NOTES_HELP = "Free-text investigation notes for this incident (up to 5,000 characters). Saved with the incident."


def _set_page(delta: int) -> None:
    st.session_state["ic_page"] = max(0, st.session_state.get("ic_page", 0) + delta)


def _focus(incident_id: int | None) -> None:
    st.session_state["ic_focus"] = incident_id


def _pick_changed() -> None:
    _focus(st.session_state.get("ic_pick"))


def _clear_filters() -> None:
    st.session_state.pop("ic_status", None)
    st.session_state["ic_page"] = 0


def _error(title: str, error: ApiError) -> None:
    st.markdown(components.error_state(title, error.user_message), unsafe_allow_html=True)


def _done(message: str, incident_id: int) -> None:
    _focus(incident_id)
    st.session_state["ic_form_n"] = st.session_state.get("ic_form_n", 0) + 1      # new form ids: the typed text is cleared
    st.toast(message, icon=":material/check_circle:")
    st.rerun()


# ---- detail and editing --------------------------------------------------------------------------

def _detail(api: ThreatScopeApi, incident_id: int) -> None:
    with st.container(key="panel-ic-detail"):
        try:
            incident = api.get_incident(incident_id)
        except ApiError as error:
            _focus(None)
            _error("Incident could not be loaded", error)
            return
        st.markdown(components.panel_heading(f"Incident #{incident.id}", "Read from the API just now. " + SCORE_NOTE), unsafe_allow_html=True)
        st.markdown(components.incident_detail(incident), unsafe_allow_html=True)
        _editor(api, incident)
        st.write("")
        st.markdown(components.panel_heading("Events in this incident", f"{incident.event_count} grouped, newest first by occurrence time (UTC)"),
                    unsafe_allow_html=True)
        st.markdown(components.events_table(incident.events, with_id=True), unsafe_allow_html=True)
        st.caption("Event IDs (copy to search on the Events page)")
        st.code("\n".join(str(e.id) for e in incident.events), language=None)


def _editor(api: ThreatScopeApi, incident) -> None:
    st.write("")
    st.markdown(components.panel_heading("Track the investigation", "Changes are saved to the incident through the API"), unsafe_allow_html=True)
    if not api.can_write:
        st.markdown(components.empty_state("Read-only", ApiWriteDisabledError.user_message), unsafe_allow_html=True)
        return
    with st.form(f"ic-edit-{incident.id}-{st.session_state.get('ic_form_n', 0)}"):
        status = st.selectbox("Status", INCIDENT_STATUSES, index=INCIDENT_STATUSES.index(incident.status),
                              format_func=STATUS_LABELS.get)
        title = st.text_input("Title", value=incident.title, max_chars=200)
        notes = st.text_area("Investigation notes", value=incident.summary or "", height=140, max_chars=5000, help=NOTES_HELP)
        saved = st.form_submit_button("Save changes", icon=":material/save:")
    if saved:
        try:
            api.update_incident(incident.id, status=status, title=title, summary=notes, clear_summary=not notes.strip())
        except ApiError as error:
            _error("Changes were not saved", error)
        else:
            _done("Incident updated", incident.id)

    with st.form(f"ic-members-{incident.id}-{st.session_state.get('ic_form_n', 0)}"):
        st.markdown(components.note("Group more related events, or take one out. IDs are separated by spaces, commas or new lines."),
                    unsafe_allow_html=True)
        add = st.text_area("Add events by ID", height=80, placeholder="7c27133f-9c0d-4878-a800-5b2278eca1f5")
        kinds = {str(e.id): e.event_type for e in incident.events}
        remove = st.multiselect("Remove events", list(kinds), format_func=lambda v: f"{kinds[v]} · {v}")
        changed = st.form_submit_button("Update events", icon=":material/library_add:")
    if changed:
        to_add, bad = parse_event_ids(add)
        if bad:
            st.markdown(components.error_state("Some IDs are not event IDs", ", ".join(bad[:5])), unsafe_allow_html=True)
        elif not to_add and not remove:
            st.markdown(components.empty_state("Nothing to change", "Enter event IDs to add or choose events to remove."), unsafe_allow_html=True)
        else:
            try:
                api.update_incident(incident.id, add_event_ids=to_add, remove_event_ids=remove)
            except ApiError as error:
                _error("Events were not updated", error)
            else:
                _done("Incident events updated", incident.id)


# ---- creating -------------------------------------------------------------------------------------------

def _create_panel(api: ThreatScopeApi) -> None:
    with st.container(key="panel-ic-create"):
        st.markdown(components.panel_heading("Create an incident", "Group related events so they can be investigated together. "
                                             "Severity and risk score are taken from the events."), unsafe_allow_html=True)
        if not api.can_write:
            st.markdown(components.empty_state("Read-only", ApiWriteDisabledError.user_message), unsafe_allow_html=True)
            return
        mode = st.radio("Group events", ["From a shared indicator", "From event IDs"], horizontal=True, key="ic_mode")
        event_ids: list[str] = []
        suggestion = ""
        if mode == "From a shared indicator":
            try:
                scan = scan_events(api)
            except ApiError as error:
                _error("Shared indicators could not be loaded", error)
                return
            clusters = correlate(scan.events)[:50]
            if not clusters:
                st.markdown(components.empty_state("No shared indicators yet", "Events must share an IP, domain, URL or file hash "
                                                   "before they can be grouped this way. You can still group events by ID."),
                            unsafe_allow_html=True)
                return
            by_id = {k.indicator.id: k for k in clusters}
            chosen = by_id[st.selectbox("Shared indicator", list(by_id), key="ic_cluster",
                                        format_func=lambda v: f"{INDICATOR_LABELS[by_id[v].indicator.type]} · "
                                        f"{redact(by_id[v].indicator.value)[:60]} · {by_id[v].count} events")]
            event_ids = [str(e.id) for e in chosen.events[:MAX_EVENT_IDS]]
            suggestion = default_title(chosen.indicator.type, chosen.indicator.value)
            st.markdown(components.note(f"{len(event_ids)} events will be grouped."
                                        + (f" (the newest {MAX_EVENT_IDS})" if chosen.count > MAX_EVENT_IDS else "")), unsafe_allow_html=True)
        else:
            raw = st.text_area("Event IDs", height=100, key="ic_ids", placeholder="One event ID per line, or separated by spaces or commas")
            event_ids, bad = parse_event_ids(raw)
            if bad:
                st.markdown(components.error_state("Some IDs are not event IDs", ", ".join(bad[:5])), unsafe_allow_html=True)
            if len(event_ids) > MAX_EVENT_IDS:
                st.markdown(components.error_state("Too many events", f"An incident takes at most {MAX_EVENT_IDS} events at a time."),
                            unsafe_allow_html=True)
        title = st.text_input("Title", value=suggestion, key=f"ic_title-{mode}-{suggestion}", max_chars=200)
        notes = st.text_area("Notes (optional)", key="ic_new_notes", height=80, max_chars=5000, help=NOTES_HELP)
        ready = bool(event_ids) and len(event_ids) <= MAX_EVENT_IDS and bool(title.strip())
        if st.button("Create incident", icon=":material/add_circle:", disabled=not ready, key="ic_create"):
            try:
                created = api.create_incident(title, event_ids, notes or None)
            except ApiError as error:
                _error("The incident was not created", error)
            else:
                _done(f"Incident #{created.id} created", created.id)


# ---- the page ---------------------------------------------------------------------------------------------

def render() -> None:
    api = require_api()
    page_header("Incidents", "Group related events and track the investigation", api)
    try:
        counts = status_counts(api)
    except ApiError as error:
        _error("Incidents are unavailable", error)
        return

    cards = [components.kpi_card("Open", counts["open"], "waiting to be looked at", "open"),
             components.kpi_card("Investigating", counts["investigating"], "being worked on", "investigating"),
             components.kpi_card("Closed", counts["closed"], "finished", "closed"),
             components.kpi_card("All incidents", counts["all"], "stored in total")]
    for column, card in zip(st.columns(4), cards):
        column.markdown(card, unsafe_allow_html=True)
    st.write("")

    with st.container(key="panel-ic-filters"):
        a, b, c = st.columns([2, 2, 1.5], vertical_alignment="bottom")
        status = a.selectbox("Status", [None, *INCIDENT_STATUSES], key="ic_status",
                             format_func=lambda v: "Any status" if v is None else STATUS_LABELS[v])
        size = b.selectbox("Rows per page", PAGE_SIZES, key="ic_size")
        c.button("Clear filters", icon=":material/filter_alt_off:", on_click=_clear_filters, use_container_width=True)
    st.write("")

    if st.session_state.get("ic_sig") != (status, size):
        st.session_state["ic_sig"], st.session_state["ic_page"] = (status, size), 0
    try:
        result = fetch_incident_page(api, status, st.session_state.get("ic_page", 0), size)
    except ApiError as error:
        _error("Incidents are unavailable", error)
        return
    st.session_state["ic_page"] = result.page

    with st.container(key="panel-ic-list"):
        st.markdown(components.panel_heading("Incidents", f"{result.total:,} match · newest first"), unsafe_allow_html=True)
        if not result.items:
            filtered = status is not None
            st.markdown(components.empty_state(
                "No incidents match" if filtered else "No incidents yet",
                "Change or clear the filter." if filtered else "Group related events into an incident with “Create an incident” below. "
                "An incident is a work item for an investigation, not a confirmed attack."), unsafe_allow_html=True)
        else:
            st.markdown(components.incidents_table(result.items), unsafe_allow_html=True)
            prev, label, nxt = st.columns([1, 3, 1], vertical_alignment="center")
            prev.button("Previous", icon=":material/chevron_left:", disabled=result.page == 0, on_click=_set_page, args=(-1,),
                        key="ic_prev", use_container_width=True)
            label.markdown(f'<div class="ts-note ts-center">Showing {result.first_item:,}–{result.last_item:,} of {result.total:,} · '
                           f'page {result.page + 1} of {result.pages}</div>', unsafe_allow_html=True)
            nxt.button("Next", icon=":material/chevron_right:", disabled=result.page + 1 >= result.pages, on_click=_set_page,
                       args=(1,), key="ic_next", use_container_width=True)
            by_id = {i.id: i for i in result.items}
            st.selectbox("Inspect an incident", [None, *by_id], key="ic_pick", on_change=_pick_changed,
                         format_func=lambda v: "Choose an incident on this page…" if v is None else f"#{v} · {redact(by_id[v].title)[:70]}")

    focus = st.session_state.get("ic_focus")
    if focus:
        _detail(api, focus)
    st.write("")
    _create_panel(api)
