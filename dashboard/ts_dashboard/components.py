"""HTML snippets for the dashboard. Pure string builders (no Streamlit), so they can be tested.

SECURITY: event text comes from outside (log lines, file contents, domains an attacker chose). Every
value that enters HTML goes through `html.escape` here; callers pass raw text, never HTML, except to
`table()` cells, which must be built by the helpers below (`cell_text`, `cell_mono`, `severity_badge`...).
"""
from datetime import datetime, timezone
from html import escape
from typing import Sequence

from ts_dashboard.models import Event, Health, Incident, Indicator
from ts_dashboard.theme import INDICATOR_LABELS, SEVERITY_COLOURS, SEVERITY_LABELS, SOURCE_LABELS

_ICON_INFO = ('<svg viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="1.8" stroke-linecap="round" '
              'stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>')
_ICON_ALERT = ('<svg viewBox="0 0 24 24" fill="none" stroke="#F43F5E" stroke-width="1.8" stroke-linecap="round" '
               'stroke-linejoin="round"><path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 10v5M12 18h.01"/></svg>')


def fmt_time(moment: datetime) -> str:
    """Always UTC and always labelled, so the table, the header and the exports agree."""
    return moment.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


def fmt_time_short(moment: datetime) -> str:
    """For narrow tables: no year (the panel subtitle says UTC)."""
    return moment.astimezone(timezone.utc).strftime("%d %b %H:%M")


def short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---- header ---------------------------------------------------------------------------------

def status_pill(label: str, state: str) -> str:
    """state: 'ok', 'bad' or 'unknown'."""
    return f'<span class="ts-pill {escape(state)}"><i></i>{escape(label)}</span>'


def health_pills(health: Health | None) -> str:
    """API and database state. `None` = the API could not be reached, so the database state is unknown."""
    if health is None:
        return status_pill("API unavailable", "bad") + status_pill("Database unknown", "unknown")
    database_up = health.database.status == "up"
    return (status_pill("API healthy", "ok")
            + status_pill("Database healthy" if database_up else "Database unavailable", "ok" if database_up else "bad"))


def page_title(title: str, description: str) -> str:
    return f'<div class="ts-title" role="heading" aria-level="1">{escape(title)}</div><div class="ts-desc">{escape(description)}</div>'


# ---- cards, panels, states ------------------------------------------------------------------

def kpi_card(label: str, value: int | str, context: str, severity: str | None = None) -> str:
    """`severity` colours the dot, and the figure too when the count is above zero (zero stays neutral)."""
    sev = f" sev-{escape(severity)}" if severity else ""
    lit = " lit" if severity and isinstance(value, int) and value > 0 else ""
    shown = f"{value:,}" if isinstance(value, int) else escape(str(value))
    return (f'<div class="ts-kpi"><div class="ts-kpi-label{sev}"><i></i>{escape(label)}</div>'
            f'<div class="ts-kpi-value{sev}{lit}">{shown}</div><div class="ts-kpi-context">{escape(context)}</div></div>')


def kpi_skeletons(count: int = 5) -> str:
    return "".join('<div class="ts-skeleton" style="margin-bottom:8px"></div>' for _ in range(count))


def panel_heading(title: str, subtitle: str = "") -> str:
    return f'<div class="ts-panel-title" role="heading" aria-level="2">{escape(title)}</div><div class="ts-panel-sub">{escape(subtitle)}</div>'


def note(text: str) -> str:
    return f'<div class="ts-note">{escape(text)}</div>'


def empty_state(title: str, text: str) -> str:
    return (f'<div class="ts-state">{_ICON_INFO}<div><div class="ts-state-title">{escape(title)}</div>'
            f'<div class="ts-state-text">{escape(text)}</div></div></div>')


def error_state(title: str, text: str) -> str:
    return (f'<div class="ts-state error" role="alert">{_ICON_ALERT}<div><div class="ts-state-title">{escape(title)}</div>'
            f'<div class="ts-state-text">{escape(text)}</div></div></div>')


# ---- table cells and table ------------------------------------------------------------------

def severity_badge(severity: str) -> str:
    known = severity if severity in SEVERITY_COLOURS else "info"
    return f'<span class="ts-badge sev-{known}">{escape(SEVERITY_LABELS.get(severity, severity))}</span>'


def cell_text(text: str, limit: int = 0) -> str:
    return escape(short(text, limit) if limit else text)


def cell_mono(text: str, limit: int = 0) -> str:
    return f'<span class="ts-mono">{escape(short(text, limit) if limit else text)}</span>'


def cell_muted(text: str) -> str:
    return f'<span class="ts-muted">{escape(text)}</span>'


def cell_nowrap(text: str) -> str:
    return f'<span class="ts-nowrap">{escape(text)}</span>'


def table(headers: Sequence[tuple[str, bool]], rows: Sequence[Sequence[str]]) -> str:
    """`headers`: (title, right_aligned). `rows`: lists of cell HTML built by the helpers above."""
    head = "".join(f'<th class="{"num" if right else ""}">{escape(title)}</th>' for title, right in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="{"num" if headers[i][1] else ""}">{cell}</td>' for i, cell in enumerate(row)) + "</tr>"
        for row in rows)
    return f'<div class="ts-table-wrap"><table class="ts-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


# ---- domain-specific rows -------------------------------------------------------------------

def primary_indicator(event: Event) -> tuple[str, str]:
    """(kind label, value) of the most telling indicator on an event, or ('', '')."""
    for kind, value in (("IP", event.source_ip), ("Domain", event.domain), ("URL", event.url), ("SHA-256", event.file_hash)):
        if value:
            return kind, value
    return "", ""


def events_table(events: Sequence[Event], with_id: bool = False) -> str:
    rows = []
    for e in events:
        kind, value = primary_indicator(e)
        rows.append([
            f'<span class="ts-nowrap ts-muted">{escape(fmt_time(e.occurred_at))}</span>',
            severity_badge(e.severity),
            f"<strong>{e.risk_score}</strong>",
            cell_text(SOURCE_LABELS.get(e.source, e.source)),
            cell_mono(e.event_type),
            cell_mono(value, 34) if value else cell_muted("none"),
            cell_text(e.description, 90),
        ] + ([cell_mono(str(e.id)[:8])] if with_id else []))
    return table([("Occurred", False), ("Severity", False), ("Risk", True), ("Source", False), ("Type", False),
                  ("Indicator", False), ("Description", False)] + ([("ID", False)] if with_id else []), rows)


def indicators_table(indicators: Sequence[Indicator]) -> str:
    rows = [[cell_nowrap(INDICATOR_LABELS.get(i.type, i.type)), cell_mono(i.value, 40), f"<strong>{i.sighting_count}</strong>",
             f'<span class="ts-nowrap ts-muted">{escape(fmt_time_short(i.last_seen))}</span>'] for i in indicators]
    return table([("Type", False), ("Value", False), ("Seen", True), ("Last seen (UTC)", False)], rows)


def high_risk_table(events: Sequence[Event]) -> str:
    rows = []
    for e in events:
        kind, value = primary_indicator(e)
        rows.append([f'<span class="ts-nowrap ts-muted">{escape(fmt_time_short(e.occurred_at))}</span>', severity_badge(e.severity),
                     f"<strong>{e.risk_score}</strong>", cell_mono(e.event_type), cell_mono(value, 28) if value else cell_muted("none")])
    return table([("Occurred (UTC)", False), ("Severity", False), ("Risk", True), ("Type", False), ("Indicator", False)], rows)


# ---- event detail ---------------------------------------------------------------------------

def definition_list(pairs: Sequence[tuple[str, str]]) -> str:
    """Label / value pairs. Values are cell HTML built by the helpers above (already escaped)."""
    items = "".join(f'<div class="ts-dl-row"><dt>{escape(label)}</dt><dd>{value}</dd></div>' for label, value in pairs)
    return f'<dl class="ts-dl">{items}</dl>'


def event_detail(event: Event) -> str:
    optional = [("Source IP", event.source_ip), ("Destination IP", event.destination_ip), ("Domain", event.domain),
                ("URL", event.url), ("File hash (SHA-256)", event.file_hash)]
    pairs = [
        ("Event ID", cell_mono(str(event.id))),
        ("External ID", cell_mono(event.external_event_id) if event.external_event_id else cell_muted("none")),
        ("Source", cell_text(SOURCE_LABELS.get(event.source, event.source))),
        ("Event type", cell_mono(event.event_type)),
        ("Severity", severity_badge(event.severity)),
        ("Risk score", f"<strong>{event.risk_score}</strong> <span class=\"ts-muted\">/ 100</span>"),
        ("Occurred", cell_text(fmt_time(event.occurred_at))),
        ("Received", cell_text(fmt_time(event.received_at))),
        ("Description", cell_text(event.description)),
    ] + [(label, cell_mono(value)) for label, value in optional if value]
    return definition_list(pairs)


def risk_factors_table(event: Event) -> str:
    if not event.risk_factors:
        return empty_state("No risk factors recorded", "The API returned no explanation for this score.")
    rows = [[cell_mono(f.rule), f"<strong>{f.points:+d}</strong>"] for f in event.risk_factors]
    rows.append([cell_muted("total (capped at 100)"), f"<strong>{event.risk_score}</strong>"])
    return table([("Rule", False), ("Points", True)], rows)


def event_indicators_table(event: Event) -> str:
    if not event.indicators:
        return empty_state("No indicators", "No IP, domain, URL or hash was extracted from this event.")
    return indicators_table(event.indicators)


# ---- indicators and correlation -------------------------------------------------------------

def indicators_full_table(indicators: Sequence[Indicator]) -> str:
    rows = [[cell_nowrap(INDICATOR_LABELS.get(i.type, i.type)), cell_mono(i.value, 60), f"<strong>{i.sighting_count}</strong>",
             f'<span class="ts-nowrap ts-muted">{escape(fmt_time(i.first_seen))}</span>',
             f'<span class="ts-nowrap ts-muted">{escape(fmt_time(i.last_seen))}</span>'] for i in indicators]
    return table([("Type", False), ("Value", False), ("Sightings", True), ("First seen", False), ("Last seen", False)], rows)


def indicator_detail(indicator: Indicator) -> str:
    return definition_list([
        ("Type", cell_text(INDICATOR_LABELS.get(indicator.type, indicator.type))),
        ("Value", cell_mono(indicator.value)),
        ("Sightings", f"<strong>{indicator.sighting_count}</strong> <span class=\"ts-muted\">(events that mentioned it, counted by the backend)</span>"),
        ("First seen", cell_text(fmt_time(indicator.first_seen))),
        ("Last seen", cell_text(fmt_time(indicator.last_seen))),
    ])


def tag(text: str) -> str:
    return f'<span class="ts-tag">{escape(text)}</span>'


def clusters_table(clusters: Sequence) -> str:
    """`clusters`: ts_dashboard.correlation.Cluster objects."""
    rows = []
    for k in clusters:
        sources = ", ".join(SOURCE_LABELS.get(s, s) for s in k.sources)
        rows.append([cell_nowrap(INDICATOR_LABELS.get(k.indicator.type, k.indicator.type)), cell_mono(k.indicator.value, 44),
                     f"<strong>{k.count}</strong>", cell_text(sources) + (" " + tag("cross-source") if k.cross_source else ""),
                     severity_badge(k.max_severity), f"<strong>{k.max_risk}</strong>",
                     f'<span class="ts-nowrap ts-muted">{escape(fmt_time_short(k.last_seen))}</span>'])
    return table([("Type", False), ("Shared indicator", False), ("Events", True), ("Sources", False), ("Highest severity", False),
                  ("Max risk", True), ("Latest (UTC)", False)], rows)


# ---- incidents ------------------------------------------------------------------------------

_STATUS_LABELS = {"open": "Open", "investigating": "Investigating", "closed": "Closed"}


def status_badge(status: str) -> str:
    known = status if status in _STATUS_LABELS else "closed"
    return f'<span class="ts-badge st-{known}">{escape(_STATUS_LABELS.get(status, status))}</span>'


def incidents_table(incidents: Sequence[Incident]) -> str:
    rows = [[f"<strong>#{i.id}</strong>", cell_text(i.title, 70), status_badge(i.status), severity_badge(i.severity),
             f"<strong>{i.risk_score}</strong>", f"{i.event_count}",
             f'<span class="ts-nowrap ts-muted">{escape(fmt_time_short(i.updated_at))}</span>'] for i in incidents]
    return table([("ID", False), ("Title", False), ("Status", False), ("Severity", False), ("Risk", True), ("Events", True),
                  ("Updated (UTC)", False)], rows)


def incident_detail(incident: Incident) -> str:
    return definition_list([
        ("Incident", f"<strong>#{incident.id}</strong>"),
        ("Title", cell_text(incident.title)),
        ("Status", status_badge(incident.status)),
        ("Severity", severity_badge(incident.severity) + ' <span class="ts-muted">highest of its events</span>'),
        ("Risk score", f'<strong>{incident.risk_score}</strong> <span class="ts-muted">/ 100, highest of its events</span>'),
        ("Events", f"<strong>{incident.event_count}</strong>"),
        ("Created", cell_text(fmt_time(incident.created_at))),
        ("Last updated", cell_text(fmt_time(incident.updated_at))),
        ("Notes", cell_text(incident.summary) if incident.summary else cell_muted("none yet")),
    ])
