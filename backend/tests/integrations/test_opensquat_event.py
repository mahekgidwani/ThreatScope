"""Finding -> ThreatScope domain event, including a round trip through the REAL API."""
import json
from datetime import datetime, timezone

import pytest

from app.schemas.event import EventIn
from integrations.client import ThreatScopeClient
from integrations.config import IntegrationSettings
from integrations.opensquat_detector import build_event, find_squatting
from tests.conftest import TEST_API_KEY

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def one(keyword, domain, confidence=1):
    [hit] = list(find_squatting([keyword], [domain], confidence_level=confidence))
    return hit


def event_for(keyword, domain, confidence=1):
    return build_event(one(keyword, domain, confidence), now=NOW)


def test_event_fields_for_a_typo():
    event = event_for("paypal", "paypa1.com")
    assert event["source"] == "domain"
    assert event["event_type"] == "domain_similarity"
    assert event["domain"] == "paypa1.com"
    assert event["occurred_at"] == NOW
    assert event["severity"] == "medium"
    assert event["external_event_id"].startswith("domain:")
    assert set(event) <= {"external_event_id", "source", "event_type", "occurred_at", "domain",
                          "severity", "description", "metadata"}


@pytest.mark.parametrize("domain, event_type", [
    ("paypa1.com", "domain_similarity"),
    ("xn--pypal-4ve.com", "domain_homograph"),
    ("paypal-secure-login.com", "domain_keyword_match"),
])
def test_event_type_follows_the_detection_kind(domain, event_type):
    assert event_for("paypal", domain)["event_type"] == event_type


@pytest.mark.parametrize("domain, confidence, severity", [
    ("paypal.xyz", 4, "medium"),       # distance 0
    ("paypa1.com", 4, "medium"),       # distance 1
    ("pyapal.com", 4, "low"),          # distance 2
    ("paypa.xyz", 4, "medium"),
    ("paypal-secure-login.com", 1, "low"),     # keyword contained
])
def test_severity_never_exceeds_medium_and_falls_with_distance(domain, confidence, severity):
    assert event_for("paypal", domain, confidence)["severity"] == severity


def test_nothing_is_called_malicious():
    event = event_for("paypal", "xn--pypal-4ve.com")
    text = (event["description"] + json.dumps(event["metadata"], default=str)).lower()
    assert "malicious" not in text
    assert event["metadata"]["verified"] is False
    assert "not a confirmed threat" in event["metadata"]["note"]
    assert "not a confirmed threat" in event["description"]


def test_metadata_explains_the_finding():
    meta = event_for("paypal", "xn--pypal-4ve.com")["metadata"]
    assert meta["keyword"] == "paypal"
    assert meta["detection"] == "homograph"
    assert meta["edit_distance"] == 0
    assert meta["confidence"] == "very high confidence"
    assert meta["compared_label"] == "paypal"
    assert meta["domain_unicode"] == "pаypal.com"
    assert meta["confidence_level_setting"] == 1


def test_contained_keyword_has_no_distance_in_metadata():
    meta = event_for("paypal", "paypal-secure-login.com")["metadata"]
    assert meta["edit_distance"] is None and meta["confidence"] is None


def test_event_passes_the_real_api_schema():
    for domain in ("paypa1.com", "xn--pypal-4ve.com", "paypal-secure-login.com"):
        EventIn.model_validate(json.loads(json.dumps(event_for("paypal", domain), default=str)))


def test_external_id_is_stable_and_separates_keywords_and_domains():
    base = event_for("paypal", "paypa1.com")["external_event_id"]
    assert event_for("paypal", "paypa1.com")["external_event_id"] == base
    assert event_for("paypal", "paypall.com")["external_event_id"] != base
    assert event_for("paypa", "paypa1.com")["external_event_id"] != base


def test_unicode_keyword_event_is_valid():
    EventIn.model_validate(json.loads(json.dumps(event_for("münchen", "muenchen.de", 4), default=str)))


def test_naive_now_is_refused():
    with pytest.raises(ValueError):
        build_event(one("paypal", "paypa1.com"), now=datetime(2026, 1, 1))


# ---- through the real application ----------------------------------------------------------

def real_client(client):
    return ThreatScopeClient(IntegrationSettings(_env_file=None, ingest_api_key=TEST_API_KEY), http_client=client)


def test_stored_scored_with_one_domain_indicator(client):
    result = real_client(client).submit_event(event_for("paypal", "paypa1.com"))
    assert result.created
    stored = client.get(f"/api/v1/events/{result.event_id}").json()
    assert stored["source"] == "domain" and stored["domain"] == "paypa1.com"
    assert stored["risk_score"] == 30                                    # medium 25 + domain 5
    assert [(i["type"], i["value"]) for i in stored["indicators"]] == [("domain", "paypa1.com")]
    assert stored["metadata"]["detection"] == "similarity"


def test_homograph_event_is_stored_as_punycode(client):
    result = real_client(client).submit_event(event_for("paypal", "xn--pypal-4ve.com"))
    stored = client.get(f"/api/v1/events/{result.event_id}").json()
    assert stored["domain"] == "xn--pypal-4ve.com"


def test_the_same_finding_twice_is_a_duplicate(client):
    api = real_client(client)
    first = api.submit_event(event_for("paypal", "paypa1.com"))
    second = api.submit_event(event_for("paypal", "paypa1.com"))
    assert second.duplicate and second.event_id == first.event_id
    assert client.get("/api/v1/events").json()["total"] == 1


def test_two_keywords_on_one_domain_are_two_events_and_raise_the_sighting_count(client):
    api = real_client(client)
    assert api.submit_event(event_for("paypal", "paypa1.com")).created
    assert api.submit_event(event_for("paypa", "paypa1.com")).created
    assert client.get("/api/v1/events").json()["total"] == 2
    [indicator] = client.get("/api/v1/indicators").json()["items"]
    assert indicator["sighting_count"] == 2
