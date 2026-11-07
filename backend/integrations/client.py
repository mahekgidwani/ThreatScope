"""The one way adapters talk to ThreatScope: `POST /api/v1/events` with the X-API-Key header.

Outcomes of `submit_event`:
  * stored            -> SubmitResult(created=True)
  * already stored    -> SubmitResult(created=False)   (HTTP 409 duplicate_event; not an error)
  * anything else     -> an `IntegrationError` subclass. `.retryable` says whether trying the
                         same event again later could work (network/timeouts/5xx) or not
                         (bad key, event rejected by validation, unreadable answer).
The client does not retry by itself; the adapter decides.

The API key is only ever put into the request header. It is never logged, and is scrubbed
from any text the server sends back before that text goes into an error message.
"""
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

import httpx

from integrations.config import IntegrationSettings

logger = logging.getLogger(__name__)

EVENTS_PATH = "/api/v1/events"
MAX_ERROR_TEXT = 300
_ID_PREFIX = re.compile(r"[A-Za-z0-9._\-]{1,40}")


# ---- errors ------------------------------------------------------------------------

class IntegrationError(Exception):
    retryable = False

    def __init__(self, message: str, status_code: int | None = None, api_code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.api_code = api_code


class ApiConnectionError(IntegrationError):
    retryable = True


class ApiTimeoutError(IntegrationError):
    retryable = True


class ApiServerError(IntegrationError):
    """The API answered 5xx (including 503 database unavailable)."""
    retryable = True


class ApiAuthError(IntegrationError):
    """401/403: the configured key is missing or wrong. Retrying will not help."""


class ApiRejectedError(IntegrationError):
    """Other 4xx, mostly 422: the event itself is invalid. Retrying the same event will not help."""


class ApiResponseError(IntegrationError):
    """A success status but an answer we cannot use (not JSON, no id, redirect...)."""


# ---- results and ids -----------------------------------------------------------------

@dataclass(frozen=True)
class SubmitResult:
    event_id: str       # the new event's id, or the id of the earlier identical event
    created: bool

    @property
    def duplicate(self) -> bool:
        return not self.created


def stable_event_id(prefix: str, *parts: object) -> str:
    """A repeatable `external_event_id` built from what identifies the event at its source.

    Same prefix + same parts -> same id, so re-reading a log or re-scanning a file cannot store
    the event twice (the API rejects the second one as a duplicate). Parts are length-safe:
    ("a", "bc") and ("ab", "c") give different ids. The result fits the API's pattern/length.
    """
    if not _ID_PREFIX.fullmatch(prefix):
        raise ValueError("prefix must be 1-40 characters of letters, digits, '.', '_' or '-'")
    digest = hashlib.sha256(json.dumps([str(part) for part in parts]).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:32]}"


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"{type(value).__name__} is not JSON serialisable")


# ---- the client ----------------------------------------------------------------------

class ThreatScopeClient:
    """`http_client` is for tests (fake server or the real app via TestClient). When it is
    not given, the client creates and owns its own `httpx.Client`."""

    def __init__(self, settings: IntegrationSettings, http_client: httpx.Client | None = None):
        self._key = settings.ingest_api_key.get_secret_value()
        self._owns_http = http_client is None
        # trust_env=False: ignore HTTP(S)_PROXY variables, so the key is never sent via a proxy.
        self._http = http_client or httpx.Client(
            base_url=settings.threatscope_api_url,
            timeout=settings.threatscope_timeout_seconds,
            trust_env=False,
        )

    def __repr__(self) -> str:
        return f"ThreatScopeClient(base_url={str(self._http.base_url)!r})"

    def __enter__(self) -> "ThreatScopeClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def submit_event(self, event: Mapping[str, Any]) -> SubmitResult:
        body = json.dumps(event, default=_json_default, allow_nan=False)
        try:
            response = self._http.post(
                EVENTS_PATH, content=body,
                headers={"X-API-Key": self._key, "Content-Type": "application/json"},
                follow_redirects=False,  # a redirect would carry the key to another place
            )
        except httpx.TimeoutException as exc:
            raise self._failed(ApiTimeoutError("timed out waiting for the ThreatScope API")) from exc
        except httpx.HTTPError as exc:
            raise self._failed(ApiConnectionError(
                f"could not reach the ThreatScope API ({type(exc).__name__})")) from exc
        return self._interpret(response)

    # -- helpers --

    def _interpret(self, response: httpx.Response) -> SubmitResult:
        status = response.status_code
        api_code, message, details = self._error_parts(response)

        if status == 201:
            event_id = self._field(response, "id")
            if event_id is None:
                raise self._failed(ApiResponseError("201 answer had no event id", status))
            logger.info("event stored (HTTP 201)")
            return SubmitResult(event_id=event_id, created=True)

        if status == 409 and api_code == "duplicate_event":
            existing = details.get("existing_id") if isinstance(details, dict) else None
            if not isinstance(existing, str):
                raise self._failed(ApiResponseError("duplicate answer had no existing id", status))
            logger.info("event already stored (HTTP 409 duplicate)")
            return SubmitResult(event_id=existing, created=False)

        text = self._describe(status, api_code, message, details)
        if status in (401, 403):
            raise self._failed(ApiAuthError(text, status, api_code))
        if 400 <= status < 500:
            raise self._failed(ApiRejectedError(text, status, api_code))
        if status >= 500:
            raise self._failed(ApiServerError(text, status, api_code))
        raise self._failed(ApiResponseError(text, status, api_code))

    @staticmethod
    def _error_parts(response: httpx.Response) -> tuple[str | None, str | None, Any]:
        """(code, message, details) from the API's {"error": {...}} body; Nones if it is not that."""
        try:
            error = response.json().get("error")
        except (ValueError, AttributeError):
            return None, None, None
        if not isinstance(error, dict):
            return None, None, None
        code, message = error.get("code"), error.get("message")
        return (code if isinstance(code, str) else None,
                message if isinstance(message, str) else None,
                error.get("details"))

    @staticmethod
    def _field(response: httpx.Response, name: str) -> str | None:
        try:
            value = response.json().get(name)
        except (ValueError, AttributeError):
            return None
        return value if isinstance(value, str) and value else None

    def _describe(self, status: int, code: str | None, message: str | None, details: Any) -> str:
        text = f"ThreatScope API answered HTTP {status}"
        if code:
            text += f" {code}"
        if message:
            text += f": {message}"
        if isinstance(details, list):  # validation errors: field path and message, never the value
            parts = [f"{'.'.join(str(p) for p in d.get('loc', []))}: {d.get('msg', '')}"
                     for d in details if isinstance(d, dict)]
            if parts:
                text += " [" + "; ".join(parts) + "]"
        return self._scrub(text)

    def _scrub(self, text: str) -> str:
        return text.replace(self._key, "***")[:MAX_ERROR_TEXT]

    def _failed(self, error: IntegrationError) -> IntegrationError:
        error.args = (self._scrub(str(error)),)
        logger.warning("ThreatScope API call failed: %s", error)
        return error
