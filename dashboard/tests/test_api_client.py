from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
import pytest

from tests.conftest import HEALTH_DOWN, HEALTH_READY, event_json, indicator_json, make_api, page_json
from ts_dashboard.api_client import (
    ApiAuthError, ApiConnectionError, ApiError, ApiNotFoundError, ApiRejectedError, ApiResponseError,
    ApiServerError, ApiTimeoutError, ThreatScopeApi,
)

ERROR_BODY = {"error": {"code": "x", "message": "boom", "details": {}}}


def json_handler(payload, status=200):
    return lambda request: httpx.Response(status, json=payload)


# ---- health ---------------------------------------------------------------------------

def test_health_ready():
    api, seen = make_api(json_handler(HEALTH_READY))
    health = api.health()
    assert (health.status, health.api.status, health.database.status, health.database.latency_ms) == ("ready", "up", "up", 3.8)
    assert seen[0].url.path == "/health"


def test_health_503_with_a_body_means_database_down_not_an_error():
    api, _ = make_api(json_handler(HEALTH_DOWN, 503))
    health = api.health()
    assert health.status == "not_ready" and health.database.status == "down" and health.api.status == "up"


def test_health_503_without_a_health_body_is_a_server_error():
    api, _ = make_api(json_handler({"error": {"code": "database_error", "message": "down", "details": {}}}, 503))
    with pytest.raises(ApiServerError) as caught:
        api.health()
    assert caught.value.status_code == 503 and caught.value.api_code == "database_error"


# ---- failures become friendly errors ----------------------------------------------------

def test_connection_failure():
    def refuse(request):
        raise httpx.ConnectError("connection refused to http://secret-host")
    api, _ = make_api(refuse)
    with pytest.raises(ApiConnectionError) as caught:
        api.health()
    assert caught.value.retryable and "backend is running" in caught.value.user_message
    assert "secret-host" not in str(caught.value)  # only the exception type is kept


def test_timeout():
    def slow(request):
        raise httpx.ReadTimeout("slow")
    api, _ = make_api(slow)
    with pytest.raises(ApiTimeoutError) as caught:
        api.list_events()
    assert caught.value.retryable


@pytest.mark.parametrize("status, error_class", [
    (401, ApiAuthError), (403, ApiAuthError), (404, ApiNotFoundError), (422, ApiRejectedError),
    (409, ApiRejectedError), (500, ApiServerError), (503, ApiServerError), (302, ApiResponseError),
])
def test_http_status_maps_to_error_class(status, error_class):
    api, _ = make_api(json_handler(ERROR_BODY, status))
    with pytest.raises(error_class) as caught:
        api.list_events()
    assert caught.value.status_code == status and caught.value.api_code == "x"
    assert isinstance(caught.value, ApiError) and caught.value.user_message


def test_redirects_are_not_followed():
    def redirect(request):
        if request.url.path == "/elsewhere":
            pytest.fail("the client followed a redirect")
        return httpx.Response(302, headers={"location": "/elsewhere"})
    api, seen = make_api(redirect)
    with pytest.raises(ApiResponseError):
        api.list_events()
    assert len(seen) == 1


@pytest.mark.parametrize("response", [
    httpx.Response(200, text="<html>not json</html>"),
    httpx.Response(200, json={"items": "nope", "total": 0, "limit": 50, "offset": 0}),
    httpx.Response(200, json=[1, 2, 3]),
    httpx.Response(200, json=page_json([event_json(severity="catastrophic")])),
    httpx.Response(200, json=page_json([event_json(risk_score=101)])),
    httpx.Response(200, json=page_json([event_json(occurred_at="2026-11-07T04:30:00")])),  # no timezone
])
def test_unusable_answers_are_reported_not_shown(response):
    api, _ = make_api(lambda request: response)
    with pytest.raises(ApiResponseError) as caught:
        api.list_events()
    assert caught.value.user_message


def test_error_text_is_one_short_clean_line():
    body = {"error": {"code": "x", "message": "line1\nline2\x00" + "a" * 1000, "details": {}}}
    api, _ = make_api(json_handler(body, 500))
    with pytest.raises(ApiServerError) as caught:
        api.list_events()
    text = str(caught.value)
    assert len(text) <= 300 and "\n" not in text and "\x00" not in text


# ---- authentication ---------------------------------------------------------------------

def test_reads_never_send_an_api_key_and_there_are_no_write_methods():
    api, seen = make_api(lambda request: httpx.Response(
        200, json=HEALTH_READY if request.url.path == "/health" else page_json([])))
    api.health(); api.list_events(); api.list_indicators(); api.list_incidents()
    assert all("x-api-key" not in request.headers for request in seen)
    assert {request.method for request in seen} == {"GET"}
    assert not [name for name in dir(ThreatScopeApi) if name.startswith(("post", "put", "patch", "delete", "create", "submit"))]


def test_a_401_from_the_api_is_reported_as_an_auth_error_with_a_message():
    api, _ = make_api(json_handler({"error": {"code": "unauthorized", "message": "Missing or invalid API key",
                                               "details": {}}}, 401))
    with pytest.raises(ApiAuthError) as caught:
        api.list_events()
    assert "authentication" in caught.value.user_message and not caught.value.retryable


def test_repr_shows_only_the_base_url():
    api, _ = make_api(json_handler(HEALTH_READY))
    assert repr(api) == "ThreatScopeApi(base_url='http://api.test')"


def test_the_real_client_ignores_proxy_environment_variables(monkeypatch):
    from ts_dashboard.config import DashboardSettings
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    with ThreatScopeApi(DashboardSettings(_env_file=None)) as api:
        assert api._http._mounts == {}  # trust_env=False: no proxy mounts were built from the environment


# ---- events: parsing, filters, pagination ---------------------------------------------------

def test_list_events_parses_a_real_shaped_page():
    api, _ = make_api(json_handler(page_json([event_json()], total=2, limit=1)))
    page = api.list_events(limit=1)
    event = page.items[0]
    assert (page.total, page.limit, page.offset, page.has_next) == (2, 1, 0, True)
    assert event.id == UUID("7c27133f-9c0d-4878-a800-5b2278eca1f5")
    assert (event.severity, event.risk_score, event.source) == ("high", 60, "honeypot")
    assert event.risk_factors[0].rule == "severity:high" and event.risk_factors[0].points == 40
    assert event.indicators[0].value == "203.0.113.42" and event.indicators[0].sighting_count == 2
    assert event.occurred_at.tzinfo is not None and event.metadata == {"rule": "9500001"}


def test_unknown_extra_fields_are_ignored():
    api, _ = make_api(json_handler(page_json([event_json(brand_new_field=1)])))
    assert api.list_events().items[0].severity == "high"


def test_empty_page():
    api, _ = make_api(json_handler(page_json([], total=0)))
    page = api.list_events()
    assert page.items == [] and page.total == 0 and not page.has_next


def test_filters_and_paging_are_sent_and_none_values_are_left_out():
    api, seen = make_api(json_handler(page_json([])))
    start = datetime(2026, 11, 7, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    api.list_events(source="honeypot", severity="high", event_type="xss_attempt", source_ip="203.0.113.42",
                    domain="evil.example", start_time=start, end_time=start + timedelta(days=1),
                    limit=25, offset=50)
    params = dict(seen[0].url.params)
    assert params == {"source": "honeypot", "severity": "high", "event_type": "xss_attempt",
                      "source_ip": "203.0.113.42", "domain": "evil.example", "limit": "25", "offset": "50",
                      "start_time": "2026-11-07T00:00:00+05:30", "end_time": "2026-11-08T00:00:00+05:30"}
    api.list_events()
    assert dict(seen[1].url.params) == {"limit": "50", "offset": "0"}


def test_naive_datetimes_are_refused_before_any_request():
    api, seen = make_api(json_handler(page_json([])))
    with pytest.raises(ValueError):
        api.list_events(start_time=datetime(2026, 11, 7))
    assert seen == []


def test_has_next_follows_offset_and_total():
    api, _ = make_api(json_handler(page_json([event_json()] * 2, total=5, limit=2, offset=2)))
    assert api.list_events(limit=2, offset=2).has_next
    api, _ = make_api(json_handler(page_json([event_json()], total=5, limit=2, offset=4)))
    assert not api.list_events(limit=2, offset=4).has_next


def test_get_event_by_id():
    api, seen = make_api(json_handler(event_json()))
    event = api.get_event("7c27133f-9c0d-4878-a800-5b2278eca1f5")
    assert event.description == "Demo XSS probe" and seen[0].url.path == "/api/v1/events/7c27133f-9c0d-4878-a800-5b2278eca1f5"


@pytest.mark.parametrize("bad_id", ["../health", "not-a-uuid", "", "7c27133f/../x"])
def test_get_event_refuses_ids_that_are_not_uuids(bad_id):
    api, seen = make_api(json_handler(event_json()))
    with pytest.raises(ValueError):
        api.get_event(bad_id)
    assert seen == []


def test_get_event_not_found():
    api, _ = make_api(json_handler({"error": {"code": "not_found", "message": "Event not found", "details": {}}}, 404))
    with pytest.raises(ApiNotFoundError):
        api.get_event("7c27133f-9c0d-4878-a800-5b2278eca1f5")


# ---- indicators and incidents ---------------------------------------------------------------

def test_list_indicators_uses_the_type_query_name():
    api, seen = make_api(json_handler(page_json([indicator_json(), indicator_json(id=2, type="sha256", value="a" * 64)])))
    page = api.list_indicators(indicator_type="sha256", value="a" * 64, limit=10, offset=5)
    assert dict(seen[0].url.params) == {"type": "sha256", "value": "a" * 64, "limit": "10", "offset": "5"}
    assert [i.type for i in page.items] == ["ip", "sha256"]


def test_list_incidents_empty_and_with_data():
    api, seen = make_api(json_handler(page_json([], total=0)))
    assert api.list_incidents(status="open").items == []
    assert dict(seen[0].url.params)["status"] == "open"
    incident = {"id": 1, "title": "Repeated XSS from one IP", "status": "investigating", "severity": "high",
                "risk_score": 70, "created_at": "2026-11-07T10:00:00Z", "updated_at": "2026-11-07T11:00:00Z",
                "summary": None}
    api, _ = make_api(json_handler(page_json([incident])))
    assert api.list_incidents().items[0].status == "investigating"
