"""The dashboard's only way to reach ThreatScope: HTTP calls to the FastAPI backend.

    Dashboard -> this client -> FastAPI -> services -> PostgreSQL

Reads (GET, no API key):
    /health   /api/v1/events   /api/v1/events/{id}   /api/v1/indicators   /api/v1/incidents   /api/v1/incidents/{id}
Incident writes (need INGEST_API_KEY, sent only as the X-API-Key header, never logged or shown):
    POST /api/v1/incidents   PATCH /api/v1/incidents/{id}

Every failure becomes an `ApiError` subclass with a plain `user_message` the UI can show as it is, so a
page never has to catch httpx or pydantic errors, and the dashboard never crashes because the API is down.
Nothing is cached here: whatever this returns was just read from the API.
"""
import logging
import re
from datetime import datetime
from typing import Any, Mapping, Sequence, TypeVar
from uuid import UUID

import httpx
from pydantic import BaseModel, ValidationError

from ts_dashboard.config import DashboardSettings
from ts_dashboard.models import Event, Health, Incident, IncidentDetail, Indicator, Page

logger = logging.getLogger(__name__)

MAX_ERROR_TEXT = 300
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
M = TypeVar("M", bound=BaseModel)


# ---- errors -----------------------------------------------------------------------------

class ApiError(Exception):
    """Base class. `str(error)` is for logs; `user_message` is for the screen."""

    retryable = False
    user_message = "ThreatScope could not complete the request."

    def __init__(self, message: str, status_code: int | None = None, api_code: str | None = None, detail: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.api_code = api_code
        self.detail = detail      # the API's own short reason (field names and rules, never the submitted values)


class ApiConnectionError(ApiError):
    retryable = True
    user_message = "Cannot reach the ThreatScope API. Check that the backend is running."


class ApiTimeoutError(ApiError):
    retryable = True
    user_message = "The ThreatScope API took too long to answer."


class ApiServerError(ApiError):
    """HTTP 5xx, including 503 'database unavailable'."""

    retryable = True
    user_message = "The ThreatScope API reported an internal problem. Check the backend and database status."


class ApiAuthError(ApiError):
    user_message = "The ThreatScope API refused the request (authentication). Check INGEST_API_KEY."


class ApiWriteDisabledError(ApiAuthError):
    """No API key is configured, so no request was sent."""

    user_message = ("Editing is turned off: this dashboard has no API key. Set INGEST_API_KEY in .env (the key the API uses) "
                    "and restart the dashboard.")


class ApiNotFoundError(ApiError):
    user_message = "That record was not found."


class ApiRejectedError(ApiError):
    """Other 4xx, mostly 422: a filter or paging value the API does not accept."""

    @property
    def user_message(self) -> str:  # type: ignore[override]
        if self.detail:
            return f"The ThreatScope API did not accept that: {self.detail}."
        return "The ThreatScope API did not accept those filters."


class ApiResponseError(ApiError):
    """A success status but an answer the dashboard cannot use (not JSON, wrong shape, redirect)."""

    user_message = "The ThreatScope API sent an answer the dashboard does not understand."


# ---- the client --------------------------------------------------------------------------

class ThreatScopeApi:
    """`http_client` is for tests; when it is not given the client creates and owns its own `httpx.Client`."""

    def __init__(self, settings: DashboardSettings, http_client: httpx.Client | None = None):
        self._owns_http = http_client is None
        self._key = settings.ingest_api_key.get_secret_value() if settings.ingest_api_key else None
        # trust_env=False: ignore HTTP(S)_PROXY variables, so requests only go where the settings say.
        self._http = http_client or httpx.Client(
            base_url=settings.threatscope_api_url,
            timeout=settings.threatscope_timeout_seconds,
            trust_env=False,
        )

    def __repr__(self) -> str:
        return f"ThreatScopeApi(base_url={str(self._http.base_url)!r})"

    def __enter__(self) -> "ThreatScopeApi":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    @property
    def can_write(self) -> bool:
        return self._key is not None

    # -- endpoints --

    def health(self) -> Health:
        """200 = ready, 503 = API up but database down. Both carry a valid body and are returned, not raised."""
        response = self._send("/health", None)
        if response.status_code in (200, 503):
            health = self._parse(response, Health, allow_error_status=True)
            if health is not None:
                return health
        return self._parse(self._ok(response), Health)

    def list_events(self, *, source: str | None = None, event_type: str | None = None,
                    severity: str | None = None, source_ip: str | None = None, domain: str | None = None,
                    start_time: datetime | None = None, end_time: datetime | None = None,
                    limit: int = 50, offset: int = 0) -> Page[Event]:
        """Newest first (the API's only order). `start_time` is inclusive, `end_time` exclusive; both need a timezone."""
        params = {"source": source, "event_type": event_type, "severity": severity, "source_ip": source_ip,
                  "domain": domain, "start_time": _iso(start_time), "end_time": _iso(end_time),
                  "limit": limit, "offset": offset}
        return self._parse(self._get("/api/v1/events", params), Page[Event])

    def get_event(self, event_id: UUID | str) -> Event:
        safe_id = UUID(str(event_id))  # raises ValueError; also stops '../' tricks reaching the URL
        return self._parse(self._get(f"/api/v1/events/{safe_id}", None), Event)

    def list_indicators(self, *, indicator_type: str | None = None, value: str | None = None,
                        limit: int = 50, offset: int = 0) -> Page[Indicator]:
        params = {"type": indicator_type, "value": value, "limit": limit, "offset": offset}
        return self._parse(self._get("/api/v1/indicators", params), Page[Indicator])

    def list_incidents(self, *, status: str | None = None, limit: int = 50, offset: int = 0) -> Page[Incident]:
        params = {"status": status, "limit": limit, "offset": offset}
        return self._parse(self._get("/api/v1/incidents", params), Page[Incident])

    def get_incident(self, incident_id: int) -> IncidentDetail:
        return self._parse(self._get(f"/api/v1/incidents/{int(incident_id)}", None), IncidentDetail)

    def create_incident(self, title: str, event_ids: Sequence[UUID | str], summary: str | None = None) -> IncidentDetail:
        """Group existing events into an incident. Severity and risk come from the events (the API decides)."""
        body: dict[str, Any] = {"title": title, "event_ids": [str(UUID(str(i))) for i in event_ids]}
        if summary:
            body["summary"] = summary
        return self._parse(self._write("POST", "/api/v1/incidents", body), IncidentDetail)

    def update_incident(self, incident_id: int, *, status: str | None = None, title: str | None = None,
                        summary: str | None = None, clear_summary: bool = False,
                        add_event_ids: Sequence[UUID | str] = (), remove_event_ids: Sequence[UUID | str] = ()) -> IncidentDetail:
        """Change only what is given. `clear_summary=True` empties the notes."""
        body: dict[str, Any] = {k: v for k, v in (("status", status), ("title", title)) if v is not None}
        if clear_summary:
            body["summary"] = None
        elif summary is not None:
            body["summary"] = summary
        if add_event_ids:
            body["add_event_ids"] = [str(UUID(str(i))) for i in add_event_ids]
        if remove_event_ids:
            body["remove_event_ids"] = [str(UUID(str(i))) for i in remove_event_ids]
        return self._parse(self._write("PATCH", f"/api/v1/incidents/{int(incident_id)}", body), IncidentDetail)

    # -- helpers --

    def _write(self, method: str, path: str, body: Mapping[str, Any]) -> httpx.Response:
        if self._key is None:
            raise ApiWriteDisabledError("no API key configured; request not sent")
        try:
            response = self._http.request(method, path, json=body, headers={"X-API-Key": self._key}, follow_redirects=False)
        except httpx.TimeoutException as exc:
            raise self._failed(ApiTimeoutError("timed out waiting for the ThreatScope API")) from exc
        except httpx.HTTPError as exc:
            raise self._failed(ApiConnectionError(f"could not reach the ThreatScope API ({type(exc).__name__})")) from exc
        return self._ok(response)

    def _get(self, path: str, params: Mapping[str, Any] | None) -> httpx.Response:
        return self._ok(self._send(path, params))

    def _send(self, path: str, params: Mapping[str, Any] | None) -> httpx.Response:
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            return self._http.get(path, params=clean or None, follow_redirects=False)
        except httpx.TimeoutException as exc:
            raise self._failed(ApiTimeoutError("timed out waiting for the ThreatScope API")) from exc
        except httpx.HTTPError as exc:
            raise self._failed(ApiConnectionError(
                f"could not reach the ThreatScope API ({type(exc).__name__})")) from exc

    def _ok(self, response: httpx.Response) -> httpx.Response:
        status = response.status_code
        if 200 <= status < 300:
            return response
        code, message, detail = self._error_parts(response)
        text = f"ThreatScope API answered HTTP {status}" + (f" {code}" if code else "")
        if message:
            text += f": {message}"
        if status in (401, 403):
            raise self._failed(ApiAuthError(text, status, code))
        if status == 404:
            raise self._failed(ApiNotFoundError(text, status, code))
        if 400 <= status < 500:
            raise self._failed(ApiRejectedError(text, status, code, detail))
        if status >= 500:
            raise self._failed(ApiServerError(text, status, code))
        raise self._failed(ApiResponseError(text, status, code))  # 1xx / 3xx: redirects are never followed

    @staticmethod
    def _error_parts(response: httpx.Response) -> tuple[str | None, str | None, str | None]:
        """(code, message, detail). `detail` = the first validation problems as 'field: rule' (the API never echoes values)."""
        try:
            error = response.json().get("error")
        except (ValueError, AttributeError):
            return None, None, None
        if not isinstance(error, dict):
            return None, None, None
        code, message, details = error.get("code"), error.get("message"), error.get("details")
        parts = []
        if isinstance(details, list):
            for d in details[:3]:
                if isinstance(d, dict) and isinstance(d.get("msg"), str):
                    where = d.get("loc")
                    field = str(where[-1]) if isinstance(where, list) and where else ""
                    parts.append(f"{field}: {d['msg']}" if field else d["msg"])
        if not parts and code == "invalid_filter" and isinstance(message, str):
            parts.append(message)         # e.g. "an incident must keep at least one event": the API's own rule text
        detail = _CONTROL_CHARS.sub(" ", "; ".join(parts))[:200] or None
        return (code if isinstance(code, str) else None), (message if isinstance(message, str) else None), detail

    def _parse(self, response: httpx.Response, model: type[M], allow_error_status: bool = False) -> M | None:
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            if allow_error_status:
                return None  # a 503 without a health body is an ordinary server error
            # Log the kind of problem only: pydantic's text may quote the API's data.
            raise self._failed(ApiResponseError(
                f"unusable answer for {model.__name__} ({type(exc).__name__})", response.status_code)) from exc

    def _failed(self, error: ApiError) -> ApiError:
        text = _CONTROL_CHARS.sub(" ", str(error))
        if self._key:
            text = text.replace(self._key, "***")     # the key must never reach a log line, whatever the server echoes
            if error.detail:
                error.detail = error.detail.replace(self._key, "***")
        error.args = (text[:MAX_ERROR_TEXT],)
        logger.warning("ThreatScope API call failed: %s", error)
        return error


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("start_time / end_time must include a timezone")
    return value.isoformat()
