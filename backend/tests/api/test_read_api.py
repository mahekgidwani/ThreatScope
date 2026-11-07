"""GET endpoints: retrieval, filters, paging, indicators, incidents, docs."""
import uuid

import pytest

from app.models import Incident
from tests.conftest import AUTH

URL = "/api/v1/events"


def post(client, **over) -> dict:
    data = {**dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
                   severity="high", description="probe"), **over}
    response = client.post(URL, json=data, headers=AUTH)
    assert response.status_code == 201, response.text
    return response.json()


def ids(response) -> list[str]:
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()["items"]]


def error_code(response) -> str:
    return response.json()["error"]["code"]


@pytest.fixture
def seeded(client):
    e1 = post(client, event_type="xss_attempt", severity="high", source_ip="203.0.113.1",
              domain="a.example", occurred_at="2026-11-07T10:00:00Z")
    e2 = post(client, event_type="sqli_attempt", severity="critical", source_ip="203.0.113.2",
              domain="b.example", occurred_at="2026-11-07T11:00:00Z")
    e3 = post(client, source="domain", event_type="typosquat_match", severity="low",
              domain="c.example", occurred_at="2026-11-07T12:00:00Z")
    e4 = post(client, source="network", event_type="port_scan", severity="medium",
              source_ip="203.0.113.1", occurred_at="2026-11-07T13:00:00Z")
    return e1["id"], e2["id"], e3["id"], e4["id"]


# ---- single event --------------------------------------------------------------

def test_get_event_returns_it_with_its_indicators(client):
    created = post(client, source_ip="203.0.113.42")
    response = client.get(f"{URL}/{created['id']}")
    assert response.status_code == 200
    assert response.json()["indicators"][0]["value"] == "203.0.113.42"


def test_unknown_event_is_404_with_the_standard_error(client):
    response = client.get(f"{URL}/{uuid.uuid4()}")
    assert response.status_code == 404 and error_code(response) == "not_found"


def test_malformed_event_id_is_422_without_echoing_it(client):
    response = client.get(f"{URL}/not-a-uuid-SECRETTOKEN")
    assert response.status_code == 422 and error_code(response) == "validation_error"
    assert "SECRETTOKEN" not in response.text


def test_reads_need_no_api_key(client):
    assert client.get(URL).status_code == 200
    assert client.get("/api/v1/indicators").status_code == 200
    assert client.get("/api/v1/incidents").status_code == 200


# ---- list: shape, paging, order ------------------------------------------------

def test_empty_list_has_the_page_shape_and_defaults(client):
    assert client.get(URL).json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_newest_first_and_paging_slices(client):
    created = [post(client, occurred_at=f"2026-11-07T{10 + h}:00:00Z")["id"] for h in range(5)]
    newest_first = list(reversed(created))
    data = client.get(URL, params={"limit": 2, "offset": 1}).json()
    assert [i["id"] for i in data["items"]] == newest_first[1:3]
    assert (data["total"], data["limit"], data["offset"]) == (5, 2, 1)
    assert ids(client.get(URL)) == newest_first
    assert ids(client.get(URL, params={"offset": 5})) == []


@pytest.mark.parametrize("params,status", [
    ({"limit": 100}, 200), ({"limit": 1}, 200), ({"limit": 101}, 422), ({"limit": 0}, 422), ({"limit": -1}, 422),
    ({"limit": "abc"}, 422), ({"offset": 0}, 200), ({"offset": -1}, 422), ({"offset": "abc"}, 422),
])
def test_limit_and_offset_bounds(client, params, status):
    response = client.get(URL, params=params)
    assert response.status_code == status
    if status == 422:
        assert error_code(response) == "validation_error"


# ---- list: filters -------------------------------------------------------------

@pytest.mark.parametrize("params,expected", [
    ({"source": "honeypot"}, {0, 1}), ({"source": "network"}, {3}), ({"event_type": "sqli_attempt"}, {1}),
    ({"severity": "low"}, {2}), ({"source_ip": "203.0.113.1"}, {0, 3}), ({"domain": "b.example"}, {1}),
    ({"start_time": "2026-11-07T11:00:00Z"}, {1, 2, 3}), ({"end_time": "2026-11-07T12:00:00Z"}, {0, 1}),
    ({"source": "honeypot", "source_ip": "203.0.113.1"}, {0}), ({}, {0, 1, 2, 3}),
])
def test_each_filter_via_query_string(client, seeded, params, expected):
    response = client.get(URL, params=params)
    assert set(ids(response)) == {seeded[i] for i in expected}
    assert response.json()["total"] == len(expected)


def test_time_range_is_inclusive_at_the_start_and_exclusive_at_the_end(client, seeded):
    params = {"start_time": "2026-11-07T10:00:00Z", "end_time": "2026-11-07T12:00:00Z"}
    assert set(ids(client.get(URL, params=params))) == {seeded[0], seeded[1]}
    ist = {"start_time": "2026-11-07T15:30:00+05:30", "end_time": "2026-11-07T17:30:00+05:30"}   # same range, +05:30
    assert set(ids(client.get(URL, params=ist))) == {seeded[0], seeded[1]}


def test_domain_and_ip_filters_are_normalised_like_ingestion(client):
    created = post(client, domain="Bücher.example", source_ip="2001:0DB8:0:0:0:0:0:1")["id"]
    for domain in ("BÜCHER.example", "xn--bcher-kva.example"):
        assert ids(client.get(URL, params={"domain": domain})) == [created], domain
    assert ids(client.get(URL, params={"source_ip": "2001:db8::1"})) == [created]


@pytest.mark.parametrize("params", [
    {"start_time": "2026-11-08T00:00:00Z", "end_time": "2026-11-07T00:00:00Z"},   # start after end
    {"start_time": "2026-11-07T10:00:00"}, {"end_time": "2026-11-07T10:00:00"},   # no timezone
    {"start_time": "yesterday"}, {"source": "email"}, {"severity": "urgent"},
    {"domain": "bad_domain!.com"}, {"domain": "%25"}, {"source_ip": "999.1.1.1"}, {"source_ip": "%25"},
])
def test_invalid_filters_are_422(client, seeded, params):
    response = client.get(URL, params=params)
    assert response.status_code == 422
    assert error_code(response) in {"validation_error", "invalid_filter"}


def test_wildcard_characters_in_event_type_are_literal(client, seeded):
    for pattern in ("%25", "xss_%25", "_ss_attempt", "%25_attempt"):          # %25 is an encoded '%'
        data = client.get(URL, params={"event_type": pattern}).json()
        assert data["total"] == 0, pattern


def test_equal_start_and_end_is_an_empty_range_not_an_error(client, seeded):
    t = "2026-11-07T11:00:00Z"
    assert client.get(URL, params={"start_time": t, "end_time": t}).json()["total"] == 0


# ---- indicators ----------------------------------------------------------------

def test_indicators_endpoint_lists_filters_and_pages(client):
    post(client, source_ip="203.0.113.1", domain="a.example")
    post(client, source_ip="203.0.113.1", domain="b.example")
    data = client.get("/api/v1/indicators").json()
    assert data["total"] == 3 and {"items", "total", "limit", "offset"} == set(data)
    only_ip = client.get("/api/v1/indicators", params={"type": "ip"}).json()
    assert only_ip["total"] == 1 and only_ip["items"][0]["sighting_count"] == 2
    exact = client.get("/api/v1/indicators", params={"type": "domain", "value": "a.example"}).json()
    assert [i["value"] for i in exact["items"]] == ["a.example"]
    assert client.get("/api/v1/indicators", params={"value": "%25"}).json()["total"] == 0
    assert client.get("/api/v1/indicators", params={"limit": 2, "offset": 2}).json()["items"].__len__() == 1


@pytest.mark.parametrize("params", [{"type": "bogus"}, {"limit": 101}, {"offset": -1}])
def test_indicators_endpoint_rejects_bad_parameters(client, params):
    assert client.get("/api/v1/indicators", params=params).status_code == 422


# ---- incidents -----------------------------------------------------------------

def test_incidents_endpoint_is_an_empty_page_until_phase_4(client):
    assert client.get("/api/v1/incidents").json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_incidents_endpoint_lists_and_filters_by_status(client, engine):
    from sqlalchemy.orm import Session
    with Session(engine) as session:
        session.add_all([Incident(title="a", severity="high", status="open"),
                         Incident(title="b", severity="low", status="closed")])
        session.commit()
    assert client.get("/api/v1/incidents").json()["total"] == 2
    open_only = client.get("/api/v1/incidents", params={"status": "open"}).json()
    assert [i["title"] for i in open_only["items"]] == ["a"]
    assert open_only["items"][0]["status"] == "open"


@pytest.mark.parametrize("params", [{"status": "bogus"}, {"limit": 0}, {"limit": 101}, {"offset": -1}])
def test_incidents_endpoint_rejects_bad_parameters(client, params):
    assert client.get("/api/v1/incidents", params=params).status_code == 422


# ---- documentation -------------------------------------------------------------

def test_interactive_docs_and_openapi_are_available(client):
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/api/v1/events", "/api/v1/events/{event_id}", "/api/v1/indicators", "/api/v1/incidents"} <= set(paths)


# ---- review fixes: hostile query values must be a 422, never a 500 -------------

HUGE = 10**20
BIGGEST = 2**63 - 1


@pytest.mark.parametrize("path", ["/api/v1/events", "/api/v1/indicators", "/api/v1/incidents"])
def test_offset_beyond_the_database_integer_range_is_422(client, path):
    for offset in (HUGE, 2**63):
        response = client.get(path, params={"offset": offset})
        assert response.status_code == 422, (path, offset, response.text)
        assert error_code(response) == "validation_error"


@pytest.mark.parametrize("path", ["/api/v1/events", "/api/v1/indicators", "/api/v1/incidents"])
def test_the_biggest_valid_offset_is_an_empty_page(client, path):
    response = client.get(path, params={"offset": BIGGEST})
    assert response.status_code == 200 and response.json()["items"] == []


@pytest.mark.parametrize("params", [
    {"event_type": "\x00"}, {"event_type": "a\x00b"},
    {"source_ip": "fe80::1%eth0"},
    {"start_time": "0001-01-01T00:00:00+05:30"}, {"end_time": "9999-12-31T23:30:00-01:00"},
], ids=["nul", "nul-inside", "ipv6-scope", "start-overflow", "end-overflow"])
def test_event_filters_the_database_cannot_represent_are_422(client, seeded, params):
    response = client.get(URL, params=params)
    assert response.status_code == 422, response.text
    assert error_code(response) == "invalid_filter"


def test_indicator_value_filter_with_nul_is_422(client):
    response = client.get("/api/v1/indicators", params={"value": "\x00"})
    assert response.status_code == 422 and error_code(response) == "invalid_filter"
