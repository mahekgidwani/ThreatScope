"""Incident endpoints: read one, create from events, change status / notes / membership.

Every test using `client` runs on in-memory SQLite and on real PostgreSQL.
"""
import time
import uuid

import pytest

from tests.conftest import AUTH, TEST_API_KEY

EVENTS = "/api/v1/events"
INCIDENTS = "/api/v1/incidents"


def make_event(client, **over) -> dict:
    data = {**dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
                   severity="high", description="probe"), **over}
    response = client.post(EVENTS, json=data, headers=AUTH)
    assert response.status_code == 201, response.text
    return response.json()


def make_incident(client, event_ids, **over) -> dict:
    response = client.post(INCIDENTS, json={"title": "Repeated probes", "event_ids": event_ids, **over}, headers=AUTH)
    assert response.status_code == 201, response.text
    return response.json()


def error_code(response) -> str:
    return response.json()["error"]["code"]


@pytest.fixture
def trio(client):
    low = make_event(client, severity="low", source="file", occurred_at="2026-11-07T09:00:00Z", file_hash="a" * 64)
    high = make_event(client, severity="high", occurred_at="2026-11-07T10:00:00Z", source_ip="203.0.113.5")
    crit = make_event(client, severity="critical", occurred_at="2026-11-07T11:00:00Z", source_ip="203.0.113.5")
    return low, high, crit


# ---- create ------------------------------------------------------------------------------------

def test_creating_needs_the_api_key(client, trio):
    body = {"title": "t", "event_ids": [trio[0]["id"]]}
    assert client.post(INCIDENTS, json=body).status_code == 401
    assert client.post(INCIDENTS, json=body, headers={"X-API-Key": "wrong-key-wrong-key"}).status_code == 401
    assert client.get(INCIDENTS).json()["total"] == 0


def test_create_groups_events_and_takes_severity_and_risk_from_them(client, trio):
    low, high, crit = trio
    created = make_incident(client, [low["id"], high["id"], crit["id"]], title="  Probes from one IP  ", summary="  first notes ")
    assert created["title"] == "Probes from one IP" and created["summary"] == "first notes"
    assert created["status"] == "open" and created["event_count"] == 3
    assert created["severity"] == "critical" and created["risk_score"] == max(e["risk_score"] for e in trio)
    assert [e["id"] for e in created["events"]] == [crit["id"], high["id"], low["id"]]       # newest first
    assert created["events"][0]["indicators"], "events come with their indicators"
    assert client.get(f"{INCIDENTS}/{created['id']}").json() == created


def test_duplicate_event_ids_count_once(client, trio):
    created = make_incident(client, [trio[1]["id"], trio[1]["id"]])
    assert created["event_count"] == 1


def test_an_unknown_event_is_404_and_nothing_is_created(client, trio):
    response = client.post(INCIDENTS, json={"title": "t", "event_ids": [trio[0]["id"], str(uuid.uuid4())]}, headers=AUTH)
    assert response.status_code == 404 and error_code(response) == "not_found"
    assert client.get(INCIDENTS).json()["total"] == 0


@pytest.mark.parametrize("body", [
    {"title": "t", "event_ids": []},
    {"title": "t"},
    {"event_ids": ["REPLACE"]},
    {"title": "   ", "event_ids": ["REPLACE"]},
    {"title": "x" * 201, "event_ids": ["REPLACE"]},
    {"title": "a\x00b", "event_ids": ["REPLACE"]},
    {"title": "t", "summary": "a\x00b", "event_ids": ["REPLACE"]},
    {"title": "t", "summary": "x" * 5001, "event_ids": ["REPLACE"]},
    {"title": "t", "event_ids": ["not-a-uuid-SECRETTOKEN"]},
    {"title": "t", "event_ids": ["REPLACE"], "severity": "critical"},        # severity is derived, never accepted
    {"title": "t", "event_ids": ["REPLACE"], "risk_score": 99},
    {"title": "t", "event_ids": ["REPLACE"], "status": "closed"},
], ids=["no-events", "no-ids", "no-title", "blank-title", "long-title", "nul-title", "nul-summary", "long-summary",
        "bad-uuid", "severity", "risk", "status"])
def test_invalid_create_requests_are_422_without_echoing_input(client, trio, body):
    body = {k: ([trio[0]["id"] if i == "REPLACE" else i for i in v] if k == "event_ids" else v) for k, v in body.items()}
    response = client.post(INCIDENTS, json=body, headers=AUTH)
    assert response.status_code == 422 and error_code(response) == "validation_error", response.text
    assert "SECRETTOKEN" not in response.text
    assert client.get(INCIDENTS).json()["total"] == 0


def test_more_than_100_events_is_422(client, trio):
    response = client.post(INCIDENTS, json={"title": "t", "event_ids": [str(uuid.uuid4()) for _ in range(101)]}, headers=AUTH)
    assert response.status_code == 422


# ---- read --------------------------------------------------------------------------------------------

def test_unknown_incident_is_404_and_a_non_number_is_422(client):
    assert client.get(f"{INCIDENTS}/999").status_code == 404
    assert error_code(client.get(f"{INCIDENTS}/999")) == "not_found"
    assert client.get(f"{INCIDENTS}/abc").status_code == 422


def test_list_shows_event_counts_and_filters_by_status(client, trio):
    a = make_incident(client, [trio[0]["id"], trio[1]["id"]], title="a")
    b = make_incident(client, [trio[2]["id"]], title="b")
    client.patch(f"{INCIDENTS}/{b['id']}", json={"status": "closed"}, headers=AUTH)
    listed = client.get(INCIDENTS).json()
    assert {i["title"]: i["event_count"] for i in listed["items"]} == {"a": 2, "b": 1}
    assert [i["title"] for i in client.get(INCIDENTS, params={"status": "closed"}).json()["items"]] == ["b"]
    assert "events" not in listed["items"][0]                       # the list stays light; detail has the events
    assert a["id"] != b["id"]


# ---- update ------------------------------------------------------------------------------------------

def test_updating_needs_the_api_key(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    assert client.patch(f"{INCIDENTS}/{incident['id']}", json={"status": "closed"}).status_code == 401
    assert client.get(f"{INCIDENTS}/{incident['id']}").json()["status"] == "open"


def test_status_moves_through_the_investigation_and_updated_at_follows(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    time.sleep(0.01)
    for status in ("investigating", "closed", "open"):
        changed = client.patch(f"{INCIDENTS}/{incident['id']}", json={"status": status}, headers=AUTH)
        assert changed.status_code == 200 and changed.json()["status"] == status
    assert changed.json()["updated_at"] > incident["updated_at"] and changed.json()["created_at"] == incident["created_at"]


def test_title_and_notes_can_be_set_and_notes_cleared(client, trio):
    incident = make_incident(client, [trio[0]["id"]], summary="old")
    url = f"{INCIDENTS}/{incident['id']}"
    changed = client.patch(url, json={"title": " New title ", "summary": "Seen at 10:00 from one IP"}, headers=AUTH).json()
    assert changed["title"] == "New title" and changed["summary"] == "Seen at 10:00 from one IP"
    assert client.patch(url, json={"summary": ""}, headers=AUTH).json()["summary"] is None
    client.patch(url, json={"summary": "again"}, headers=AUTH)
    assert client.patch(url, json={"summary": None}, headers=AUTH).json()["summary"] is None
    assert client.patch(url, json={"status": "closed"}, headers=AUTH).json()["title"] == "New title"   # untouched fields stay


@pytest.mark.parametrize("body", [
    {}, {"status": "bogus"}, {"status": None}, {"title": None}, {"title": " "}, {"summary": "a\x00b"},
    {"severity": "low"}, {"risk_score": 1}, {"add_event_ids": ["x"]},
], ids=["empty", "bad-status", "null-status", "null-title", "blank-title", "nul", "severity", "risk", "bad-id"])
def test_invalid_updates_are_422_and_change_nothing(client, trio, body):
    incident = make_incident(client, [trio[0]["id"]])
    response = client.patch(f"{INCIDENTS}/{incident['id']}", json=body, headers=AUTH)
    assert response.status_code == 422 and error_code(response) == "validation_error", response.text
    assert client.get(f"{INCIDENTS}/{incident['id']}").json() == incident


def test_adding_and_removing_events_recomputes_severity_risk_and_count(client, trio):
    low, high, crit = trio
    incident = make_incident(client, [low["id"]])
    url = f"{INCIDENTS}/{incident['id']}"
    assert (incident["severity"], incident["event_count"]) == ("low", 1)
    grown = client.patch(url, json={"add_event_ids": [high["id"], crit["id"]]}, headers=AUTH).json()
    assert (grown["severity"], grown["event_count"], grown["risk_score"]) == ("critical", 3, max(e["risk_score"] for e in trio))
    assert grown["updated_at"] >= incident["updated_at"]
    shrunk = client.patch(url, json={"remove_event_ids": [crit["id"]]}, headers=AUTH).json()
    assert (shrunk["severity"], shrunk["event_count"], shrunk["risk_score"]) == ("high", 2, high["risk_score"])
    assert {e["id"] for e in shrunk["events"]} == {low["id"], high["id"]}
    again = client.patch(url, json={"add_event_ids": [high["id"]], "remove_event_ids": [crit["id"]]}, headers=AUTH).json()
    assert again["event_count"] == 2                                  # re-adding a member and removing a non-member are no-ops


def test_an_incident_keeps_at_least_one_event(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    response = client.patch(f"{INCIDENTS}/{incident['id']}", json={"remove_event_ids": [trio[0]["id"]]}, headers=AUTH)
    assert response.status_code == 422 and error_code(response) == "invalid_filter"
    assert client.get(f"{INCIDENTS}/{incident['id']}").json()["event_count"] == 1


def test_an_unknown_event_in_an_update_is_404_and_nothing_changes(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    response = client.patch(f"{INCIDENTS}/{incident['id']}", headers=AUTH,
                            json={"status": "closed", "add_event_ids": [trio[1]["id"], str(uuid.uuid4())]})
    assert response.status_code == 404
    assert client.get(f"{INCIDENTS}/{incident['id']}").json() == incident         # status and membership both untouched


def test_the_same_event_cannot_be_added_and_removed_at_once(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    response = client.patch(f"{INCIDENTS}/{incident['id']}", json={"add_event_ids": [trio[1]["id"]], "remove_event_ids": [trio[1]["id"]]}, headers=AUTH)
    assert response.status_code == 422


def test_updating_an_unknown_incident_is_404(client):
    assert client.patch(f"{INCIDENTS}/999", json={"status": "closed"}, headers=AUTH).status_code == 404


def test_deleting_an_event_row_does_not_break_reading_its_incident(client, engine, trio):
    from sqlalchemy import delete
    from sqlalchemy.orm import Session
    from app.models import Event
    incident = make_incident(client, [trio[0]["id"], trio[1]["id"]])
    with Session(engine) as session:
        session.execute(delete(Event).where(Event.id == uuid.UUID(trio[0]["id"])))
        session.commit()
    after = client.get(f"{INCIDENTS}/{incident['id']}").json()
    assert after["event_count"] == 1 and [e["id"] for e in after["events"]] == [trio[1]["id"]]


def test_the_key_never_appears_in_responses(client, trio):
    incident = make_incident(client, [trio[0]["id"]])
    assert TEST_API_KEY not in client.get(f"{INCIDENTS}/{incident['id']}").text
    assert TEST_API_KEY not in client.patch(f"{INCIDENTS}/{incident['id']}", json={"status": "closed"}, headers=AUTH).text


def test_openapi_lists_the_new_operations(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert {"get"} == set(paths[f"{INCIDENTS}/{{incident_id}}"]) - {"patch"}
    assert "post" in paths[INCIDENTS] and "patch" in paths[f"{INCIDENTS}/{{incident_id}}"]


# ---- id range ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("incident_id", [2_147_483_648, 99_999_999_999, 0, -1])
def test_incident_id_outside_int4_is_rejected_not_a_500(client, incident_id):
    url = f"{INCIDENTS}/{incident_id}"
    assert error_code(client.get(url)) == "validation_error"
    assert client.get(url).status_code == 422
    patched = client.patch(url, json={"status": "closed"}, headers=AUTH)
    assert patched.status_code == 422 and error_code(patched) == "validation_error"


def test_largest_int4_incident_id_that_does_not_exist_is_404(client):
    url = f"{INCIDENTS}/2147483647"
    assert client.get(url).status_code == 404
    assert client.patch(url, json={"status": "closed"}, headers=AUTH).status_code == 404
