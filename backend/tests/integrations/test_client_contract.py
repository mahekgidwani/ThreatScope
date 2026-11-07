"""The client against the REAL ThreatScope application (SQLite and PostgreSQL), so the contract
it relies on - endpoint, header, status codes, error shape - is checked, not assumed."""
import pytest

from integrations.client import ApiAuthError, ApiRejectedError, ThreatScopeClient, stable_event_id
from integrations.config import IntegrationSettings
from tests.conftest import TEST_API_KEY


def real_api_client(client, key=TEST_API_KEY):
    config = IntegrationSettings(_env_file=None, ingest_api_key=key)
    return ThreatScopeClient(config, http_client=client)


def honeypot_event(**overrides):
    event = {"external_event_id": stable_event_id("contract", "one"), "source": "honeypot",
             "event_type": "sql_injection", "severity": "high", "occurred_at": "2026-01-01T00:00:00Z",
             "source_ip": "203.0.113.9", "description": "contract test event"}
    return {**event, **overrides}


def test_event_is_stored_scored_and_indicators_extracted(client):
    result = real_api_client(client).submit_event(honeypot_event())
    assert result.created

    stored = client.get(f"/api/v1/events/{result.event_id}").json()
    assert stored["source"] == "honeypot"
    assert stored["risk_score"] > 0
    assert [(i["type"], i["value"]) for i in stored["indicators"]] == [("ip", "203.0.113.9")]


def test_same_external_id_twice_gives_duplicate_with_the_original_id(client):
    api = real_api_client(client)
    first = api.submit_event(honeypot_event())
    second = api.submit_event(honeypot_event())
    assert first.created and second.duplicate
    assert second.event_id == first.event_id
    assert client.get("/api/v1/events").json()["total"] == 1


def test_wrong_api_key_is_an_auth_error(client):
    with pytest.raises(ApiAuthError):
        real_api_client(client, key="not-the-key-0123456789abcdef").submit_event(honeypot_event())
    assert client.get("/api/v1/events").json()["total"] == 0


def test_invalid_event_is_rejected_with_field_details_and_nothing_stored(client):
    with pytest.raises(ApiRejectedError) as caught:
        real_api_client(client).submit_event(honeypot_event(domain="not a domain"))
    assert caught.value.status_code == 422
    assert "domain" in str(caught.value)
    assert client.get("/api/v1/events").json()["total"] == 0
