"""Integration tests against the REAL running stack: this dashboard code -> FastAPI -> PostgreSQL.

They only READ (no incident or event is created, nothing is deleted) and they need the backend running
(`docker compose up -d`). They are excluded from the normal run so the mocked tests stay independent of Docker;
run them with:  python -m pytest -m live -p no:cacheprovider
If the backend is down they FAIL, never skip: a skipped integration test proves nothing.
"""
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from ts_dashboard import charts, components
from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.config import DashboardSettings
from ts_dashboard.correlation import correlate, scan_events
from ts_dashboard.events import EventFilters, fetch_event_page
from ts_dashboard.incidents import status_counts
from ts_dashboard.models import (
    ApiHealth, DatabaseHealth, Event, Health, Incident, IncidentDetail, Indicator, RiskFactor, SEVERITIES, SOURCES,
)
from ts_dashboard.overview import load_overview
from ts_dashboard.reports import build_report, events_to_csv, fetch_export, report_markdown

pytestmark = pytest.mark.live
BASE = DashboardSettings(_env_file=None).threatscope_api_url


@pytest.fixture(scope="module")
def api():
    with ThreatScopeApi(DashboardSettings(_env_file=None, ingest_api_key=None)) as client:
        yield client


def test_the_backend_is_up_with_a_healthy_database(api):
    health = api.health()
    assert (health.status, health.api.status, health.database.status) == ("ready", "up", "up")
    assert health.database.latency_ms is not None


def test_dashboard_models_match_the_apis_published_schema():
    """If the backend renames or drops a field the dashboard reads, this fails (the mocked tests cannot notice)."""
    schemas = json.load(urllib.request.urlopen(f"{BASE}/openapi.json"))["components"]["schemas"]
    expected = {"EventOut": Event, "IndicatorOut": Indicator, "IncidentOut": Incident, "IncidentDetailOut": IncidentDetail,
                "HealthOut": Health, "ApiHealth": ApiHealth, "DatabaseHealth": DatabaseHealth, "RiskFactor": RiskFactor}
    for name, model in expected.items():
        assert name in schemas, name
        missing = set(model.model_fields) - set(schemas[name]["properties"])
        assert not missing, f"{model.__name__} reads fields the API no longer sends: {missing}"
    assert set(schemas["Severity"]["enum"]) == set(SEVERITIES) and set(schemas["Source"]["enum"]) == set(SOURCES)


def test_events_page_matches_the_apis_own_total(api):
    page = fetch_event_page(api, EventFilters(), 0, 25)
    raw = json.load(urllib.request.urlopen(f"{BASE}/api/v1/events?limit=1"))
    assert page.total == raw["total"] and len(page.items) == min(25, raw["total"])
    assert all(isinstance(e, Event) for e in page.items)
    if page.items:
        assert api.get_event(page.items[0].id).id == page.items[0].id


def test_oldest_first_really_is_the_other_end_of_the_data(api):
    newest = fetch_event_page(api, EventFilters(), 0, 100)
    oldest = fetch_event_page(api, EventFilters(), 0, 100, ascending=True)
    assert newest.total == oldest.total
    if newest.total <= 100:                                    # whole data set on one page: the two orders must mirror each other
        assert [e.id for e in oldest.items] == [e.id for e in reversed(newest.items)]


def test_overview_numbers_are_internally_consistent(api):
    data = load_overview(api)
    assert sum(data.by_severity.values()) == data.total_events == sum(data.by_source.values())
    assert data.total_events >= len(data.recent_events) and data.total_incidents >= data.open_incidents


def test_report_and_csv_export_over_real_data(api):
    report = build_report(api, EventFilters())
    assert report.total == sum(report.by_severity.values())
    events, total = fetch_export(api, EventFilters())
    assert total == report.total and len(events) == min(total, 5000)
    csv_text = events_to_csv(events).decode("utf-8-sig")
    assert len(csv_text.splitlines()) >= 1 + len(events)       # header + rows (descriptions may add lines)
    assert "# ThreatScope summary report" in report_markdown(report)


def test_correlation_over_real_events_only_uses_stored_indicators(api):
    scan = scan_events(api)
    for cluster in correlate(scan.events):
        assert cluster.count >= 2 and all(any(i.id == cluster.indicator.id for i in e.indicators) for e in cluster.events)


def test_incident_counts_agree_with_the_list(api):
    counts = status_counts(api)
    assert counts["all"] == counts["open"] + counts["investigating"] + counts["closed"]


def test_reads_are_open_and_writes_need_the_key():
    def status(method, path, body=None):
        request = urllib.request.Request(f"{BASE}{path}", data=body, method=method, headers={"Content-Type": "application/json"})
        try:
            return urllib.request.urlopen(request).status
        except urllib.error.HTTPError as error:
            return error.code
    assert status("GET", "/api/v1/incidents") == 200
    # Invalid body ({}) on purpose: if auth ever failed open these answer 422 and change nothing in the real data.
    assert status("POST", "/api/v1/incidents", b"{}") == 401
    assert status("PATCH", "/api/v1/incidents/1", b"{}") == 401


def test_the_real_app_renders_every_page_against_the_real_api():
    for page in ("overview", "events", "indicators", "correlation", "incidents", "reports", "status"):
        import os
        os.environ["TS_PAGE"] = page
        at = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "ui" / "harness.py"), default_timeout=90).run()
        assert not at.exception, (page, [e.value for e in at.exception])
        html = "\n".join(m.value for m in at.markdown)
        assert "API healthy" in html and "Database healthy" in html, page
        assert "is unavailable" not in html and "could not" not in html.lower(), page
    os.environ.pop("TS_PAGE", None)
