"""Reports and exports, built only from stored data read through the API.

Exact numbers: the number of events in scope and the split by severity and by source are `total`s of filtered
`limit=1` queries. Sampled numbers: event types, recurring indicators and the high-risk list come from the newest
REPORT_SAMPLE events in scope (and the newest HIGH_RISK_SCAN critical/high events); the report always says how
many were analysed. Risk scores are shown as the backend computed them and are labelled experimental.

CSV exports neutralise spreadsheet formulas (a cell that starts with = + - @ is prefixed with an apostrophe) and
hide secrets in metadata and URLs, because event text comes from outside.
"""
import csv
import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.events import EventFilters
from ts_dashboard.incidents import status_counts
from ts_dashboard.models import Event, IncidentDetail, Indicator, SEVERITIES, SOURCES
from ts_dashboard.paging import fetch_up_to
from ts_dashboard.redact import redact
from ts_dashboard.theme import INDICATOR_LABELS, SCORE_NOTE, SEVERITY_LABELS, SOURCE_LABELS

REPORT_SAMPLE = 1000
HIGH_RISK_SCAN = 200
HIGH_RISK_SHOWN = 10
RECURRING_SHOWN = 10
TYPES_SHOWN = 10
EXPORT_MAX = 5000
HIGH_RISK_SEVERITIES = ("critical", "high")
CSV_COLUMNS = ("event_id", "external_event_id", "occurred_at_utc", "received_at_utc", "source", "event_type", "severity", "risk_score",
               "source_ip", "destination_ip", "domain", "url", "file_hash", "description", "indicators", "metadata_json")
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class Recurring:
    indicator: Indicator
    events_in_scope: int


@dataclass(frozen=True)
class Report:
    generated_at: datetime
    scope: EventFilters
    total: int
    by_severity: dict[str, int]
    by_source: dict[str, int]
    analysed: int
    event_types: list[tuple[str, int]]
    high_risk: list[Event]
    recurring: list[Recurring]
    incidents: dict[str, int]

    @property
    def truncated(self) -> bool:
        return self.analysed < self.total

    @property
    def high_risk_sampled(self) -> bool:
        return any(self.by_severity[s] > HIGH_RISK_SCAN for s in HIGH_RISK_SEVERITIES)


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_scope(scope: EventFilters) -> str:
    parts = []
    if scope.source:
        parts.append(f"source {SOURCE_LABELS.get(scope.source, scope.source)}")
    if scope.severity:
        parts.append(f"severity {SEVERITY_LABELS.get(scope.severity, scope.severity)}")
    if scope.event_type:
        parts.append(f"type {scope.event_type}")
    if scope.start_time:
        parts.append(f"from {_utc(scope.start_time)}")
    if scope.end_time:
        parts.append(f"before {_utc(scope.end_time)}")
    return ", ".join(parts) if parts else "all stored events"


def recurring_indicators(events: list[Event], limit: int = RECURRING_SHOWN) -> list[Recurring]:
    """Indicators that appear in 2+ of `events`, most events first (ties: more recent sighting, then value)."""
    seen: dict[int, tuple[Indicator, int]] = {}
    for event in events:
        for indicator in event.indicators:
            current = seen.get(indicator.id)
            seen[indicator.id] = (indicator, (current[1] if current else 0) + 1)
    found = [Recurring(i, n) for i, n in seen.values() if n >= 2]
    return sorted(found, key=lambda r: (-r.events_in_scope, -r.indicator.last_seen.timestamp(), r.indicator.value))[:limit]


def build_report(api: ThreatScopeApi, scope: EventFilters, now: datetime | None = None) -> Report:
    """Raises ApiError when any call fails: the page shows one error, never a half-filled report."""
    now = now or datetime.now(timezone.utc)
    base = scope.params()
    total = api.list_events(**base, limit=1).total
    by_severity = {s: (api.list_events(**{**base, "severity": s}, limit=1).total if scope.severity in (None, s) else 0)
                   for s in SEVERITIES}
    by_source = {s: (api.list_events(**{**base, "source": s}, limit=1).total if scope.source in (None, s) else 0)
                 for s in SOURCES}
    sample, _ = fetch_up_to(api.list_events, REPORT_SAMPLE, **base)
    types = Counter(e.event_type for e in sample).most_common(TYPES_SHOWN)
    candidates: list[Event] = []
    for severity in HIGH_RISK_SEVERITIES:
        if scope.severity in (None, severity):
            found, _ = fetch_up_to(api.list_events, HIGH_RISK_SCAN, **{**base, "severity": severity})
            candidates += found
    high_risk = sorted(candidates, key=lambda e: (-e.risk_score, -e.occurred_at.timestamp(), str(e.id)))[:HIGH_RISK_SHOWN]
    return Report(now, scope, total, by_severity, by_source, len(sample), types, high_risk, recurring_indicators(sample),
                  status_counts(api))


# ---- CSV ---------------------------------------------------------------------------------------------------

def csv_safe(value: object) -> object:
    """Stop a spreadsheet from running text as a formula. Numbers and None pass through unchanged."""
    if isinstance(value, str) and value.startswith(_FORMULA_STARTS):
        return "'" + value
    return value


def event_csv_row(event: Event) -> list[object]:
    safe = redact({"description": event.description, "url": event.url, "metadata": event.metadata})
    indicators = "; ".join(f"{i.type}:{i.value}" for i in event.indicators)
    row = [str(event.id), event.external_event_id, _utc(event.occurred_at), _utc(event.received_at), event.source, event.event_type,
           event.severity, event.risk_score, event.source_ip, event.destination_ip, event.domain, safe["url"], event.file_hash,
           safe["description"], redact(indicators), json.dumps(safe["metadata"], ensure_ascii=False, sort_keys=True)]
    return [csv_safe(cell) for cell in row]


def events_to_csv(events: list[Event]) -> bytes:
    """UTF-8 with a byte-order mark, so Excel reads accented text correctly."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for event in events:
        writer.writerow(event_csv_row(event))
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def fetch_export(api: ThreatScopeApi, scope: EventFilters, limit: int = EXPORT_MAX) -> tuple[list[Event], int]:
    """Newest events in scope (up to `limit`) and the total number in scope."""
    return fetch_up_to(api.list_events, limit, **scope.params())


# ---- Markdown summaries ----------------------------------------------------------------------------------

def _cell(text: object) -> str:
    return redact(str(text)).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _event_rows(events: list[Event]) -> list[list[object]]:
    rows = []
    for e in events:
        indicator = redact(e.source_ip or e.domain or e.url or e.file_hash or "none")   # before the cut
        rows.append([str(e.id), _utc(e.occurred_at), e.event_type, SEVERITY_LABELS[e.severity], e.risk_score, indicator[:60]])
    return rows


def report_markdown(report: Report) -> str:
    lines = ["# ThreatScope summary report", "", f"Generated {_utc(report.generated_at)} UTC from data read through the ThreatScope API.",
             f"Scope: {describe_scope(report.scope)}.", "", f"> {SCORE_NOTE} Severity is the label the detecting source gave the event.", "",
             "## Events", "", f"{report.total:,} events in scope."]
    if report.truncated:
        lines.append(f"The event types, recurring indicators and the high-risk list below were computed from the newest {report.analysed:,} "
                     f"of {report.total:,} events.")
    lines += ["", "### By severity", ""] + _table(["Severity", "Events"], [[SEVERITY_LABELS[s], report.by_severity[s]] for s in SEVERITIES[::-1]])
    lines += ["", "### By source", ""] + _table(["Source", "Events"], [[SOURCE_LABELS[s], report.by_source[s]] for s in SOURCES])
    if report.event_types:
        lines += ["", "### Most frequent event types", ""] + _table(["Event type", "Events"], [list(t) for t in report.event_types])
    lines += ["", "## High-risk events", "", "Critical and high severity events with the highest experimental risk scores"
              + (f", from the newest {HIGH_RISK_SCAN} per severity." if report.high_risk_sampled else "."), ""]
    lines += _table(["Event ID", "Occurred (UTC)", "Type", "Severity", "Risk", "Indicator"], _event_rows(report.high_risk)) if report.high_risk \
        else ["None in scope."]
    lines += ["", "## Recurring indicators", "", "Indicators found in more than one event of this scope. A recurring indicator is a lead, not proof of malicious activity.", ""]
    lines += _table(["Type", "Value", "Events in scope", "Sightings (all time)"],
                    [[INDICATOR_LABELS.get(r.indicator.type, r.indicator.type), r.indicator.value, r.events_in_scope, r.indicator.sighting_count]
                     for r in report.recurring]) if report.recurring else ["None in scope."]
    lines += ["", "## Incidents", "", f"{report.incidents['all']} stored: {report.incidents['open']} open, "
              f"{report.incidents['investigating']} investigating, {report.incidents['closed']} closed.", ""]
    return "\n".join(lines)


def incident_markdown(incident: IncidentDetail, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    lines = [f"# Incident #{incident.id}: {_cell(incident.title)}", "", f"Generated {_utc(now)} UTC from data read through the ThreatScope API.", "",
             f"- Status: {incident.status}", f"- Severity: {SEVERITY_LABELS[incident.severity]} (highest of its events)",
             f"- Risk score: {incident.risk_score} / 100 (highest of its events)", f"- Created: {_utc(incident.created_at)}",
             f"- Last updated: {_utc(incident.updated_at)}", f"- Events: {incident.event_count}", "", f"> {SCORE_NOTE}", "",
             "## Investigation notes", "", redact(incident.summary) if incident.summary else "No notes recorded.", "", "## Events", ""]
    lines += _table(["Event ID", "Occurred (UTC)", "Type", "Severity", "Risk", "Indicator"], _event_rows(incident.events))
    shared = recurring_indicators(incident.events, 20)
    lines += ["", "## Indicators shared by these events", ""]
    lines += _table(["Type", "Value", "Events here"], [[INDICATOR_LABELS.get(r.indicator.type, r.indicator.type), r.indicator.value, r.events_in_scope]
                                                      for r in shared]) if shared else ["None."]
    lines += ["", "An incident is a work item for an investigation, not a confirmed attack.", ""]
    return "\n".join(lines)
