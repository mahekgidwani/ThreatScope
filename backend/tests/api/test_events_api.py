"""POST /api/v1/events and the cross-cutting API behaviour (auth, errors, logging)."""
import logging
import uuid

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

import app.api.events as events_module
from tests.conftest import AUTH, TEST_API_KEY

URL = "/api/v1/events"


def body(**over) -> dict:
    return {**dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
                   severity="high", description="probe"), **over}


def error_of(response) -> dict:
    data = response.json()
    assert set(data) == {"error"} and {"code", "message", "details"} <= set(data["error"])
    return data["error"]


# ---- authentication ------------------------------------------------------------

@pytest.mark.parametrize("headers", [
    {}, {"X-API-Key": ""}, {"X-API-Key": "wrong-key-wrong-key-wrong"}, {"X-API-Key": TEST_API_KEY + " "},
    {"X-API-Key": TEST_API_KEY[:-1]}, {"X-API-Key": TEST_API_KEY.upper()},
    {"Authorization": f"Bearer {TEST_API_KEY}"}, {"x-api-key": ("ü" * 8).encode("latin-1")},   # raw non-ASCII bytes on the wire
], ids=["missing", "empty", "wrong", "trailing-space", "truncated", "uppercased", "bearer-instead", "non-ascii"])
def test_post_without_the_right_key_is_401(client, headers):
    response = client.post(URL, json=body(), headers=headers)
    assert response.status_code == 401
    assert error_of(response)["code"] == "unauthorized"
    assert TEST_API_KEY not in response.text


def test_rejected_write_does_not_store_anything(client):
    client.post(URL, json=body())
    assert client.get(URL).json()["total"] == 0


def test_valid_key_creates_the_event(client):
    response = client.post(URL, json=body(source_ip="203.0.113.42", url="http://evil.example/a",
                                          metadata={"rule": "9500001"}, external_event_id="ext-1"), headers=AUTH)
    assert response.status_code == 201
    data = response.json()
    assert uuid.UUID(data["id"]).version == 4
    assert data["external_event_id"] == "ext-1"
    assert data["received_at"].endswith("Z") and data["occurred_at"] == "2026-11-07T10:00:00Z"
    assert (data["severity"], data["risk_score"]) == ("high", 55)
    assert data["risk_factors"] == [{"rule": "severity:high", "points": 40}, {"rule": "source:honeypot", "points": 15}]
    assert data["metadata"] == {"rule": "9500001"} and "event_metadata" not in data
    assert {(i["type"], i["value"]) for i in data["indicators"]} == {
        ("ip", "203.0.113.42"), ("url", "http://evil.example/a"), ("domain", "evil.example")}
    assert TEST_API_KEY not in response.text


def test_response_can_be_fetched_again_identically(client):
    created = client.post(URL, json=body(source_ip="203.0.113.42"), headers=AUTH).json()
    assert client.get(f"{URL}/{created['id']}").json() == created


def test_unicode_domain_is_stored_as_punycode(client):
    data = client.post(URL, json=body(domain="Bücher.Example."), headers=AUTH).json()
    assert data["domain"] == "xn--bcher-kva.example"
    assert [(i["type"], i["value"]) for i in data["indicators"]] == [("domain", "xn--bcher-kva.example")]


def test_risk_bonus_grows_over_the_api(client):
    scores = [client.post(URL, json=body(source_ip="203.0.113.42"), headers=AUTH).json()["risk_score"]
              for _ in range(3)]
    assert scores == [55, 60, 65]


# ---- validation ----------------------------------------------------------------

@pytest.mark.parametrize("field,value", [("id", str(uuid.uuid4())), ("risk_score", 99), ("received_at", "2026-01-01T00:00:00Z"),
                                         ("risk_factors", []), ("unknown_field", 1)])
def test_server_owned_and_unknown_fields_are_422(client, field, value):
    response = client.post(URL, json=body(**{field: value}), headers=AUTH)
    assert response.status_code == 422
    assert error_of(response)["code"] == "validation_error"


def test_validation_errors_name_the_field_but_never_echo_the_input(client):
    response = client.post(URL, json=body(
        source_ip="999.1.1.1-SECRETTOKEN", external_event_id="has space SECRETTOKEN", url="javascript:SECRETTOKEN",
        event_type="Bad SECRETTOKEN", file_hash="zz-SECRETTOKEN", domain="bad_SECRETTOKEN!.com"), headers=AUTH)
    assert response.status_code == 422
    assert "SECRETTOKEN" not in response.text
    details = error_of(response)["details"]
    assert all(set(d) == {"loc", "type", "msg"} for d in details)
    fields = {d["loc"][-1] for d in details}
    assert {"source_ip", "external_event_id", "url", "event_type", "file_hash", "domain"} <= fields


@pytest.mark.parametrize("content", ["{bad json", "[]", '"text"', "", "null"])
def test_malformed_bodies_are_422_with_the_standard_shape(client, content):
    response = client.post(URL, content=content, headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 422
    assert error_of(response)["code"] == "validation_error"


def test_naive_and_numeric_timestamps_are_422(client):
    for value in ("2026-11-07T10:00:00", 1700000000, "1700000000"):
        assert client.post(URL, json=body(occurred_at=value), headers=AUTH).status_code == 422


# ---- duplicates ----------------------------------------------------------------

def test_duplicate_external_id_is_409_with_the_existing_id(client):
    first = client.post(URL, json=body(external_event_id="ext-1"), headers=AUTH).json()
    second = client.post(URL, json=body(external_event_id="ext-1", description="again"), headers=AUTH)
    assert second.status_code == 409
    error = error_of(second)
    assert error["code"] == "duplicate_event" and error["details"] == {"existing_id": first["id"]}
    assert client.get(URL).json()["total"] == 1


def test_same_external_id_on_another_source_is_allowed(client):
    assert client.post(URL, json=body(external_event_id="ext-1"), headers=AUTH).status_code == 201
    assert client.post(URL, json=body(external_event_id="ext-1", source="domain"), headers=AUTH).status_code == 201


# ---- error handling ------------------------------------------------------------

def test_unknown_route_and_wrong_method_use_the_standard_error_shape(client):
    missing = client.get("/api/v1/nope")
    assert missing.status_code == 404 and error_of(missing)["code"] == "not_found"
    wrong = client.delete(URL, headers=AUTH)
    assert wrong.status_code == 405 and error_of(wrong)["code"] == "method_not_allowed"


def test_database_outage_is_a_generic_503_without_internals(client, monkeypatch, caplog):
    def explode(*args, **kwargs):
        raise OperationalError("SELECT secret_table", {"pw": "hunter2"}, Exception("password=hunter2 host=10.1.2.3"))

    monkeypatch.setattr(events_module, "create_event", explode)
    with caplog.at_level(logging.ERROR):
        response = client.post(URL, json=body(), headers=AUTH)
    assert response.status_code == 503
    assert error_of(response)["code"] == "database_error"
    for leaked in ("hunter2", "10.1.2.3", "secret_table", "Traceback", "OperationalError"):
        assert leaked not in response.text
    assert any(record.exc_info for record in caplog.records)      # the details went to the log instead


@pytest.mark.parametrize("exc", [RuntimeError("boom-SECRETTOKEN"), IntegrityError("INSERT x", {}, Exception("dup SECRETTOKEN"))])
def test_unexpected_errors_are_a_generic_500(client, monkeypatch, exc):
    def explode(*args, **kwargs):
        raise exc

    monkeypatch.setattr(events_module, "create_event", explode)
    response = client.post(URL, json=body(), headers=AUTH)
    assert response.status_code == 500
    assert error_of(response)["code"] == "internal_error"
    assert "SECRETTOKEN" not in response.text


# ---- logging -------------------------------------------------------------------

def test_request_log_has_method_path_status_and_never_the_key_or_query(client, caplog):
    with caplog.at_level(logging.DEBUG):
        client.post(URL, json=body(description="body-SECRETTOKEN"), headers=AUTH)
        client.get(URL, params={"domain": "query-SECRETTOKEN.example"})
        client.post(URL, json=body(), headers={"X-API-Key": "wrong-key-SECRETTOKEN-xx"})
    # Look only at the server's own loggers: the test client (httpx) logs its own request URLs.
    server_logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("app"))
    assert TEST_API_KEY not in server_logs
    assert "SECRETTOKEN" not in server_logs
    assert TEST_API_KEY not in caplog.text          # the key must not appear in ANY log line
    lines = [r.getMessage() for r in caplog.records if r.name == "app.access"]
    assert any(line.startswith("POST '/api/v1/events' 201 ") for line in lines)
    assert any(line.startswith("GET '/api/v1/events' 200 ") for line in lines)
    assert any(line.startswith("POST '/api/v1/events' 401 ") for line in lines)


def test_access_log_does_not_contain_raw_newlines_from_the_path(client, caplog):
    with caplog.at_level(logging.DEBUG):
        client.get("/x%0A2026-11-10 12:00:00,000 ERROR app.x forged")
    lines = [r.getMessage() for r in caplog.records if r.name == "app.access"]
    assert lines and not any("\n" in line or "\r" in line for line in lines)
    assert any("\\n2026-11-10" in line for line in lines)      # the escaped form is what gets logged


# ---- request size cap (BACK-01) -------------------------------------------------

def test_oversized_body_is_413_with_the_error_envelope(client):
    from app.main import MAX_REQUEST_BYTES
    payload = "SECRETPAYLOAD" * (MAX_REQUEST_BYTES // 10)           # > 256 KiB, no API key sent
    for url, extra in ((URL, {}), ("/api/v1/incidents", {"event_ids": []})):
        response = client.post(url, json={"title": payload, **extra})
        assert response.status_code == 413
        error = error_of(response)
        assert error["code"] == "payload_too_large"
        assert "SECRETPAYLOAD" not in response.text


def test_a_body_under_the_cap_is_not_a_413(client):
    # ~200 KiB of metadata passes the size middleware and is refused by max_metadata_bytes (422).
    response = client.post(URL, json=body(metadata={"k": "x" * 200_000}), headers=AUTH)
    assert response.status_code == 422
    assert error_of(response)["code"] == "validation_error"


def test_a_non_numeric_content_length_does_not_crash_the_middleware(client):
    response = client.post(URL, content=b"{}", headers={"Content-Length": "abc", "Content-Type": "application/json"})
    assert response.status_code != 500


@pytest.mark.parametrize("field, limit", [("domain", 512), ("source_ip", 64), ("destination_ip", 64)])
def test_overlong_event_fields_are_422(client, field, limit):
    over = client.post(URL, json=body(**{field: "a" * (limit + 1)}), headers=AUTH)
    assert over.status_code == 422
    assert error_of(over)["details"][0]["type"] == "string_too_long"
    at = client.post(URL, json=body(**{field: "a" * limit}), headers=AUTH)   # refused by the existing rules, not the length
    assert all(d["type"] != "string_too_long" for d in error_of(at)["details"])


# ---- review fixes: input the database cannot store must be a 422, never a 500 --

@pytest.mark.parametrize("over", [
    dict(description="a\x00b"), dict(metadata={"k": "a\x00b"}), dict(metadata={"a\x00": 1}),
    dict(metadata={"k": [{"deep": "\x00"}]}),
    dict(domain="pay­pal.com"), dict(domain="１２７.0.0.1"),
    dict(occurred_at="0001-01-01T00:00:00+05:30"), dict(occurred_at="9999-12-31T23:30:00-01:00"),
    dict(source_ip="fe80::1%eth0"), dict(destination_ip="fe80::1%" + "a" * 60),
], ids=["nul-description", "nul-meta-value", "nul-meta-key", "nul-meta-nested", "soft-hyphen-domain",
        "fullwidth-ip-domain", "year-1-overflow", "year-9999-overflow", "ipv6-scope", "ipv6-long-scope"])
def test_values_postgresql_cannot_store_are_422_not_500(client, over):
    response = client.post(URL, json=body(**over), headers=AUTH)
    assert response.status_code == 422, response.text
    assert error_of(response)["code"] == "validation_error"
    assert client.get(URL).json()["total"] == 0


def test_a_lookalike_domain_is_never_stored_as_the_real_one(client):
    assert client.post(URL, json=body(domain="pay­pal.com"), headers=AUTH).status_code == 422
    stored = client.post(URL, json=body(domain="paypal.com"), headers=AUTH).json()
    assert stored["domain"] == "paypal.com" and stored["indicators"][0]["sighting_count"] == 1


def test_sharp_s_domain_is_stored_under_its_own_name(client):
    data = client.post(URL, json=body(domain="faß.de"), headers=AUTH).json()
    assert data["domain"] == "xn--fa-hia.de"


def test_the_earliest_and_latest_representable_timestamps_round_trip(client):
    for sent, expected in (("0001-01-01T05:30:00+05:30", "0001-01-01T00:00:00Z"),
                           ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z")):
        created = client.post(URL, json=body(occurred_at=sent), headers=AUTH)
        assert created.status_code == 201, created.text
        assert client.get(f"{URL}/{created.json()['id']}").json()["occurred_at"] == expected


def test_text_with_ordinary_control_characters_round_trips(client):
    created = client.post(URL, json=body(description="line1\nline2\ttab", metadata={"k": "a\nb\u001f"}),
                          headers=AUTH).json()
    assert client.get(f"{URL}/{created['id']}").json()["description"] == "line1\nline2\ttab"
