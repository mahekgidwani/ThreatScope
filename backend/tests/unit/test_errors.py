"""The application's own exception types (mapped to HTTP responses in Task 8)."""
import uuid

from app.errors import AppError, AuthError, DuplicateEventError, InvalidFilterError, NotFoundError


def test_duplicate_event_error_carries_the_existing_id():
    existing = uuid.uuid4()
    err = DuplicateEventError(existing)
    assert isinstance(err, AppError)
    assert (err.status_code, err.code) == (409, "duplicate_event")
    assert err.existing_id == existing
    assert err.details == {"existing_id": str(existing)}


def test_not_found_error():
    err = NotFoundError("event")
    assert (err.status_code, err.code) == (404, "not_found")
    assert "event" in err.message


def test_auth_error_message_does_not_hint_at_the_key():
    err = AuthError()
    assert (err.status_code, err.code) == (401, "unauthorized")
    assert err.details == {}


def test_invalid_filter_error():
    err = InvalidFilterError("start_time must not be after end_time")
    assert (err.status_code, err.code) == (422, "invalid_filter")
    assert err.message == "start_time must not be after end_time"


def test_app_error_defaults():
    err = AppError()
    assert (err.status_code, err.code, err.details) == (500, "internal_error", {})
    assert str(err) == err.message
