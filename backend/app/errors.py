"""The application's own error types.

Services raise these; Task 8 turns them into HTTP responses of one uniform shape:
{"error": {"code": ..., "message": ..., "details": {...}}}
"""
from uuid import UUID


class AppError(Exception):
    status_code = 500
    code = "internal_error"
    message = "Internal server error"

    def __init__(self, message: str | None = None, details: dict | None = None):
        self.message = message or type(self).message
        self.details = details or {}
        super().__init__(self.message)


class DuplicateEventError(AppError):
    status_code = 409
    code = "duplicate_event"
    message = "An event with this source and external_event_id already exists"

    def __init__(self, existing_id: UUID):
        self.existing_id = existing_id
        super().__init__(details={"existing_id": str(existing_id)})


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"

    def __init__(self, what: str):
        super().__init__(f"{what} not found")


class AuthError(AppError):
    status_code = 401
    code = "unauthorized"
    message = "Missing or invalid API key"


class InvalidFilterError(AppError):
    """A query parameter or paging value is invalid (HTTP 422)."""

    status_code = 422
    code = "invalid_filter"
    message = "Invalid filter"
