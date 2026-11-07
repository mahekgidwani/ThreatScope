import csv
import io
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import make_api
from tests.fake_backend import FakeBackend, T0, event, incident, indicator
from ts_dashboard import reports as rp
from ts_dashboard.events import EventFilters
from ts_dashboard.models import Event, IncidentDetail

NOW = T0 + timedelta(days=1)
IP = indicator(1, "ip", "203.0.113.42", sightings=4)
DOM = indicator(2, "domain", "evil.example", sightings=2)


def api_for(backend):
    return make_api(backend)[0]


def parsed(*raw):
    return [Event.model_validate(r) for r in raw]


def sample_backend():
    events = [
        event(1, severity="critical", risk=90, source="honeypot", event_type="sqli_attempt", source_ip="203.0.113.42", indicators=[IP]),
        event(2, severity="high", risk=60, source="honeypot", event_type="xss_attempt", source_ip="203.0.113.42", indicators=[IP, DOM]),
        event(3, severity="high", risk=70, source="domain", event_type="domain_similarity", domain="evil.example", indicators=[DOM]),
        event(4, severity="low", risk=20, source="file", event_type="file_analysis", at=T0 + timedelta(days=3)),
        event(5, severity="info", risk=5, source="file", event_type="file_analysis"),
    ]
    return FakeBackend(events=events, indicators=[IP, DOM], incidents=[incident(1, "open", "high", (events[0]["id"],)), incident(2, "closed")])


def read_csv(blob: bytes) -> list[dict]:
    assert blob.startswith("﻿".encode("utf-8"))
    return list(csv.DictReader(io.StringIO(blob.decode("utf-8-sig"), newline="")))


# ---- the report ---------------------------------------------------------------------------------------

def test_exact_counts_split_by_severity_and_source():
    report = rp.build_report(api_for(sample_backend()), EventFilters(), NOW)
    assert report.total == 5 and not report.truncated
    assert report.by_severity == {"info": 1, "low": 1, "medium": 0, "high": 2, "critical": 1}
    assert report.by_source == {"domain": 1, "honeypot": 2, "file": 2, "network": 0}
    assert report.incidents == {"open": 1, "investigating": 0, "closed": 1, "all": 2}


def test_scope_filters_narrow_every_number():
    report = rp.build_report(api_for(sample_backend()), EventFilters(source="honeypot"), NOW)
    assert report.total == 2 and sum(report.by_severity.values()) == 2 and report.by_source["file"] == 0 and report.by_source["honeypot"] == 2
    sev = rp.build_report(api_for(sample_backend()), EventFilters(severity="high"), NOW)
    assert sev.total == 2 and sev.by_severity["high"] == 2 and sev.by_severity["critical"] == 0
    assert {e.severity for e in sev.high_risk} == {"high"}
    windowed = rp.build_report(api_for(sample_backend()), EventFilters(start_time=T0 + timedelta(days=2)), NOW)
    assert windowed.total == 1 and windowed.by_severity["low"] == 1


def test_high_risk_is_critical_and_high_ordered_by_risk_then_time():
    report = rp.build_report(api_for(sample_backend()), EventFilters(), NOW)
    assert [e.risk_score for e in report.high_risk] == [90, 70, 60]
    assert all(e.severity in ("critical", "high") for e in report.high_risk)


def test_high_risk_list_is_capped(monkeypatch):
    monkeypatch.setattr(rp, "HIGH_RISK_SHOWN", 2)
    assert len(rp.build_report(api_for(sample_backend()), EventFilters(), NOW).high_risk) == 2


def test_event_types_and_recurring_indicators_come_from_the_events_in_scope():
    report = rp.build_report(api_for(sample_backend()), EventFilters(), NOW)
    assert dict(report.event_types)["file_analysis"] == 2
    assert [(r.indicator.value, r.events_in_scope) for r in report.recurring] == [("203.0.113.42", 2), ("evil.example", 2)]
    only_file = rp.build_report(api_for(sample_backend()), EventFilters(source="file"), NOW)
    assert only_file.recurring == []


def test_the_sample_is_capped_and_the_report_says_so(monkeypatch):
    monkeypatch.setattr(rp, "REPORT_SAMPLE", 3)
    report = rp.build_report(api_for(sample_backend()), EventFilters(), NOW)
    assert report.total == 5 and report.analysed == 3 and report.truncated
    assert report.by_severity["high"] == 2                      # counts stay exact
    assert "newest 3 of 5" in rp.report_markdown(report)


def test_empty_database():
    report = rp.build_report(api_for(FakeBackend()), EventFilters(), NOW)
    assert report.total == 0 and report.analysed == 0 and report.high_risk == [] and report.recurring == [] and report.event_types == []
    text = rp.report_markdown(report)
    assert "0 events in scope" in text and text.count("None in scope.") == 2


def test_recurring_indicators_ties_and_limit():
    evts = parsed(*[event(n, indicators=[indicator(i, "ip", f"10.0.0.{i}", sightings=i)]) for n in range(1, 3) for i in range(1, 6)])
    top = rp.recurring_indicators(evts, 3)
    assert len(top) == 3 and all(r.events_in_scope == 2 for r in top)
    assert rp.recurring_indicators(parsed(event(1, indicators=[IP]))) == []


def test_only_reads_and_api_failure_propagates():
    backend = sample_backend()
    rp.build_report(api_for(backend), EventFilters(), NOW)
    assert {r.method for r in backend.requests} == {"GET"}
    from ts_dashboard.api_client import ApiConnectionError
    with pytest.raises(ApiConnectionError):
        rp.build_report(api_for(FakeBackend(down=True)), EventFilters(), NOW)


def test_scope_description():
    assert rp.describe_scope(EventFilters()) == "all stored events"
    text = rp.describe_scope(EventFilters(source="honeypot", severity="high", start_time=T0))
    assert "source Honeypot" in text and "severity High" in text and "from 2026-11-07T04:00:00Z" in text


# ---- CSV --------------------------------------------------------------------------------------------------------

def test_csv_has_one_row_per_event_with_every_column_and_utc_times():
    rows = read_csv(rp.events_to_csv(parsed(*sample_backend().events)))
    assert len(rows) == 5 and tuple(rows[0]) == rp.CSV_COLUMNS
    first = next(r for r in rows if r["external_event_id"] == "ext-2")
    assert first["occurred_at_utc"] == "2026-11-07T04:02:00Z" and first["severity"] == "high" and first["risk_score"] == "60"
    assert first["indicators"] == "ip:203.0.113.42; domain:evil.example" and first["source_ip"] == "203.0.113.42"


def test_csv_with_no_events_is_just_the_header():
    rows = rp.events_to_csv([]).decode("utf-8-sig").splitlines()
    assert rows == [",".join(rp.CSV_COLUMNS)]


@pytest.mark.parametrize("text", ["=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\tTAB", "\rCR"])
def test_formula_like_text_is_neutralised(text):
    assert rp.csv_safe(text) == "'" + text
    row = read_csv(rp.events_to_csv(parsed(event(1, description=text + " rest"))))[0]
    assert row["description"].startswith("'")


def test_normal_values_are_not_changed():
    assert rp.csv_safe("hello") == "hello" and rp.csv_safe(42) == 42 and rp.csv_safe(None) is None and rp.csv_safe("") == ""
    assert read_csv(rp.events_to_csv(parsed(event(1, description="Plain text, with comma and \"quotes\"\nand a new line"))))[0]["description"] \
        == "Plain text, with comma and \"quotes\"\nand a new line"


def test_secrets_are_hidden_in_csv_metadata_url_and_description():
    evt = event(1, description="login via http://admin:hunter2@evil.example/x", url="http://bob:pw123@evil.example/a",
                metadata={"api_key": "SUPERSECRET", "nested": {"password": "hunter2", "rule": "9500001"}})
    blob = rp.events_to_csv(parsed(evt)).decode("utf-8")
    assert "SUPERSECRET" not in blob and "hunter2" not in blob and "pw123" not in blob and "9500001" in blob and "[redacted]" in blob


def test_csv_keeps_unicode():
    assert "Büchér — 検査" in read_csv(rp.events_to_csv(parsed(event(1, description="Büchér — 検査"))))[0]["description"]


def test_export_fetches_in_scope_up_to_the_limit():
    backend = FakeBackend(events=[event(n, severity="high" if n % 2 else "low") for n in range(1, 251)])
    events, total = rp.fetch_export(api_for(backend), EventFilters(severity="high"), limit=100)
    assert (len(events), total) == (100, 125) and {e.severity for e in events} == {"high"}
    assert rp.fetch_export(api_for(FakeBackend()), EventFilters()) == ([], 0)


# ---- Markdown ---------------------------------------------------------------------------------------------------

def test_report_markdown_has_every_section_and_the_caveats():
    text = rp.report_markdown(rp.build_report(api_for(sample_backend()), EventFilters(source="honeypot"), NOW))
    for expected in ("# ThreatScope summary report", "Scope: source Honeypot", "2 events in scope", "### By severity", "### By source",
                     "## High-risk events", "## Recurring indicators", "## Incidents", "Experimental prioritisation score", "not a probability of compromise",
                     "not proof of malicious activity", "203.0.113.42", "| Critical | 1 |"):
        assert expected in text, expected


def test_markdown_cells_cannot_break_the_table():
    detail = IncidentDetail.model_validate({**incident(1, "open", "high", ()), "event_count": 1, "title": "a | b\nc", "summary": "see http://u:secret@x.example",
                                           "events": [event(1, source_ip="1.2.3.4|x")]})
    text = rp.incident_markdown(detail, NOW)
    assert "a \\| b c" in text and "1.2.3.4\\|x" in text and "secret" not in text


def test_incident_summary_lists_notes_events_and_shared_indicators():
    events = [event(1, severity="high", risk=60, indicators=[IP]), event(2, severity="critical", risk=95, indicators=[IP, DOM])]
    detail = IncidentDetail.model_validate({**incident(7, "investigating", "critical", ()), "risk_score": 95, "event_count": 2, "summary": "Same IP twice.",
                                           "title": "Repeated probes", "events": events})
    text = rp.incident_markdown(detail, NOW)
    for expected in ("# Incident #7: Repeated probes", "Status: investigating", "Risk score: 95 / 100", "Same IP twice.", events[0]["id"], events[1]["id"],
                     "## Indicators shared by these events", "203.0.113.42", "not a confirmed attack", "not a probability of compromise"):
        assert expected in text, expected
    assert "No notes recorded." in rp.incident_markdown(IncidentDetail.model_validate({**incident(8, "open", "low", ()), "event_count": 1, "events": [event(3)]}), NOW)
