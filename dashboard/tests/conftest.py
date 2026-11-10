import httpx
import pytest

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.config import DashboardSettings

BASE = "http://api.test"


def make_api(handler) -> tuple[ThreatScopeApi, list[httpx.Request]]:
    """A client wired to `handler(request) -> httpx.Response`; also returns every request it made."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(recording))
    return ThreatScopeApi(DashboardSettings(_env_file=None, ingest_api_key=None), http_client=http), seen


@pytest.fixture(autouse=True)
def no_real_api_key(monkeypatch):
    """Keep the developer's real INGEST_API_KEY (env or .env) out of every test; tests that need a key set their own."""
    monkeypatch.setenv("INGEST_API_KEY", "")


@pytest.fixture
def api_for():
    return make_api


def indicator_json(**over):
    return {"id": 1, "type": "ip", "value": "203.0.113.42", "first_seen": "2026-11-07T10:47:44.202889Z",
            "last_seen": "2026-11-07T10:47:44.584549Z", "sighting_count": 2, **over}


def event_json(**over):
    return {"id": "7c27133f-9c0d-4878-a800-5b2278eca1f5", "external_event_id": "demo-002", "source": "honeypot",
            "event_type": "xss_attempt", "occurred_at": "2026-11-07T04:30:00Z",
            "received_at": "2026-11-07T10:47:44.584549Z", "source_ip": "203.0.113.42", "destination_ip": None,
            "domain": None, "url": None, "file_hash": None, "severity": "high", "risk_score": 60,
            "risk_factors": [{"rule": "severity:high", "points": 40}], "description": "Demo XSS probe",
            "metadata": {"rule": "9500001"}, "indicators": [indicator_json()], **over}


def page_json(items, total=None, limit=50, offset=0):
    return {"items": items, "total": len(items) if total is None else total, "limit": limit, "offset": offset}


HEALTH_READY = {"status": "ready", "api": {"status": "up"}, "database": {"status": "up", "latency_ms": 3.8}}
HEALTH_DOWN = {"status": "not_ready", "api": {"status": "up"}, "database": {"status": "down", "latency_ms": None}}
