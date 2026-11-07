"""The shared API client, tested against fake servers so every failure mode can be produced."""
import json
import logging
import socket
import threading
from datetime import datetime, timezone

import httpx
import pytest

from integrations.client import (
    ApiAuthError, ApiConnectionError, ApiRejectedError, ApiResponseError, ApiServerError,
    ApiTimeoutError, IntegrationError, ThreatScopeClient, stable_event_id,
)
from integrations.config import IntegrationSettings

KEY = "k3y-for-tests-0123456789abcdef"
EVENT = {"source": "honeypot", "event_type": "sql_injection", "severity": "high",
         "occurred_at": "2026-01-01T00:00:00Z", "description": "test event",
         "external_event_id": "mod:abc"}


def settings(**overrides):
    return IntegrationSettings(_env_file=None, ingest_api_key=KEY, **overrides)


def client_with(handler):
    """A ThreatScopeClient whose HTTP layer is a Python function instead of a network."""
    http = httpx.Client(base_url="http://testserver", transport=httpx.MockTransport(handler))
    return ThreatScopeClient(settings(), http_client=http)


def json_reply(status, body):
    return httpx.Response(status, json=body)


def api_error(status, code, message="m", details=None):
    return json_reply(status, {"error": {"code": code, "message": message, "details": details or {}}})


# ---- success and request shape --------------------------------------------------

def test_submit_posts_json_to_the_events_endpoint_with_the_api_key():
    seen = {}

    def handler(request):
        seen["method"], seen["path"] = request.method, request.url.path
        seen["key"] = request.headers.get("x-api-key")
        seen["body"] = json.loads(request.content)
        return json_reply(201, {"id": "11111111-1111-1111-1111-111111111111"})

    result = client_with(handler).submit_event(EVENT)

    assert (seen["method"], seen["path"]) == ("POST", "/api/v1/events")
    assert seen["key"] == KEY
    assert seen["body"] == EVENT
    assert result.created and not result.duplicate
    assert result.event_id == "11111111-1111-1111-1111-111111111111"


def test_datetimes_are_sent_as_iso_text():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return json_reply(201, {"id": "x"})

    event = {**EVENT, "occurred_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)}
    client_with(handler).submit_event(event)
    assert seen["body"]["occurred_at"] == "2026-01-01T12:00:00+00:00"


def test_redirects_are_not_followed_because_the_key_would_travel_with_them():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(307, headers={"location": "http://elsewhere.invalid/steal"})

    with pytest.raises(ApiResponseError):
        client_with(handler).submit_event(EVENT)
    assert calls == ["/api/v1/events"]


# ---- duplicates ---------------------------------------------------------------------

def test_duplicate_is_a_normal_result_not_an_error():
    def handler(request):
        return api_error(409, "duplicate_event", details={"existing_id": "abc-123"})

    result = client_with(handler).submit_event(EVENT)
    assert result.duplicate and not result.created
    assert result.event_id == "abc-123"


def test_409_with_another_code_is_a_rejection():
    with pytest.raises(ApiRejectedError):
        client_with(lambda r: api_error(409, "something_else")).submit_event(EVENT)


# ---- API says no ------------------------------------------------------------------

def test_401_raises_auth_error_and_is_not_retryable():
    with pytest.raises(ApiAuthError) as caught:
        client_with(lambda r: api_error(401, "unauthorized")).submit_event(EVENT)
    assert caught.value.retryable is False
    assert caught.value.status_code == 401


def test_422_raises_rejected_with_the_field_details_and_is_not_retryable():
    details = [{"loc": ["body", "domain"], "type": "value_error", "msg": "domain is not valid"}]
    with pytest.raises(ApiRejectedError) as caught:
        client_with(lambda r: api_error(422, "validation_error", "Request validation failed", details)
                    ).submit_event(EVENT)
    assert caught.value.retryable is False
    assert caught.value.status_code == 422
    assert caught.value.api_code == "validation_error"
    assert "domain is not valid" in str(caught.value)


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_are_retryable(status):
    with pytest.raises(ApiServerError) as caught:
        client_with(lambda r: api_error(status, "internal_error")).submit_event(EVENT)
    assert caught.value.retryable is True
    assert caught.value.status_code == status


def test_all_errors_share_one_base_class():
    for exc in (ApiAuthError, ApiConnectionError, ApiRejectedError, ApiResponseError,
                ApiServerError, ApiTimeoutError):
        assert issubclass(exc, IntegrationError)


# ---- the API answers nonsense -----------------------------------------------------

@pytest.mark.parametrize("reply", [
    httpx.Response(201, text="<html>proxy page</html>"),   # not JSON
    httpx.Response(201, json=["not", "an", "object"]),      # JSON, wrong shape
    httpx.Response(201, json={"no_id": True}),              # missing id
    httpx.Response(200, json={"id": "x"}),                  # success but not 201
    httpx.Response(500, text="boom"),                       # error with no JSON body (still a server error)
])
def test_unexpected_responses(reply):
    with pytest.raises(IntegrationError):
        client_with(lambda r: reply).submit_event(EVENT)


def test_non_json_201_is_a_response_error_not_a_crash():
    with pytest.raises(ApiResponseError):
        client_with(lambda r: httpx.Response(201, text="<html>")).submit_event(EVENT)


def test_422_without_a_json_body_still_raises_rejected():
    with pytest.raises(ApiRejectedError):
        client_with(lambda r: httpx.Response(422, text="nope")).submit_event(EVENT)


# ---- network failures ---------------------------------------------------------------

def test_connection_error_is_retryable():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(ApiConnectionError) as caught:
        client_with(handler).submit_event(EVENT)
    assert caught.value.retryable is True


def test_timeout_is_retryable():
    def handler(request):
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ApiTimeoutError) as caught:
        client_with(handler).submit_event(EVENT)
    assert caught.value.retryable is True


def test_real_closed_port_raises_connection_error():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]  # nothing listens here once the probe closes
    with ThreatScopeClient(settings(threatscope_api_url=f"http://127.0.0.1:{port}",
                                    threatscope_timeout_seconds=2)) as client:
        with pytest.raises(ApiConnectionError):
            client.submit_event(EVENT)


def test_real_silent_server_hits_the_timeout():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    accepted = []
    threading.Thread(target=lambda: accepted.append(server.accept()), daemon=True).start()
    try:
        port = server.getsockname()[1]
        with ThreatScopeClient(settings(threatscope_api_url=f"http://127.0.0.1:{port}",
                                        threatscope_timeout_seconds=0.3)) as client:
            with pytest.raises(ApiTimeoutError):
                client.submit_event(EVENT)
    finally:
        for conn, _ in accepted:
            conn.close()
        server.close()


# ---- secrets ------------------------------------------------------------------------

def test_key_echoed_by_the_server_is_scrubbed_from_error_text():
    def handler(request):
        return api_error(422, "validation_error", f"bad request, key was {KEY}")

    with pytest.raises(ApiRejectedError) as caught:
        client_with(handler).submit_event(EVENT)
    assert KEY not in str(caught.value)
    assert KEY not in repr(caught.value)


def test_logs_never_contain_the_key_or_the_event_body(caplog):
    caplog.set_level(logging.DEBUG)
    secret_text = "very-private-description-text"
    event = {**EVENT, "description": secret_text}

    def handler(request):
        return api_error(401, "unauthorized", f"echo {KEY}")

    for reply in (handler, lambda r: json_reply(201, {"id": "x"})):
        try:
            client_with(reply).submit_event(event)
        except IntegrationError:
            pass
    assert KEY not in caplog.text
    assert secret_text not in caplog.text


def test_client_repr_does_not_show_the_key():
    assert KEY not in repr(client_with(lambda r: json_reply(201, {"id": "x"})))


# ---- stable external ids --------------------------------------------------------------

def test_stable_event_id_is_deterministic():
    assert stable_event_id("modsec", "10.0.0.1", "line 5") == stable_event_id("modsec", "10.0.0.1", "line 5")


def test_stable_event_id_changes_when_any_part_changes():
    base = stable_event_id("modsec", "a", "b")
    assert stable_event_id("modsec", "a", "c") != base
    assert stable_event_id("opensquat", "a", "b") != base


def test_stable_event_id_does_not_confuse_where_one_part_ends():
    assert stable_event_id("p", "a", "bc") != stable_event_id("p", "ab", "c")


def test_stable_event_id_is_accepted_by_the_api_pattern():
    import re
    value = stable_event_id("modsec", "x" * 5000, "ünïcode")
    assert re.fullmatch(r"[A-Za-z0-9._:\-]+", value)
    assert len(value) <= 128
    assert value.startswith("modsec:")


@pytest.mark.parametrize("bad_prefix", ["", "has space", "bad/slash", "x" * 100])
def test_stable_event_id_refuses_a_prefix_the_api_would_reject(bad_prefix):
    with pytest.raises(ValueError):
        stable_event_id(bad_prefix, "a")
