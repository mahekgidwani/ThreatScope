"""The application's own error types, and how every error becomes an HTTP response.

Every error the API returns has exactly this shape:
    {"error": {"code": "...", "message": "...", "details": {...}}}
Responses never contain SQL, stack traces, credentials or the client's raw input; those go
to the log instead.
"""
import logging
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.common import ErrorBody, ErrorResponse

logger = logging.getLogger(__name__)


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


# ---- HTTP mapping --------------------------------------------------------------

_HTTP_CODES = {404: ("not_found", "Not found"), 405: ("method_not_allowed", "Method not allowed")}


def error_response(status_code: int, code: str, message: str, details=None) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message,
                                         details={} if details is None else details))
    return JSONResponse(status_code=status_code, content=body.model_dump())


def _safe_validation_details(exc: RequestValidationError) -> list[dict]:
    """Field path, error type and message only. The submitted value is never included."""
    details = []
    for err in exc.errors():
        message = err["msg"]
        if err["type"] == "uuid_parsing":   # pydantic's own text quotes a piece of the input
            message = "Input should be a valid UUID"
        details.append({"loc": [str(part) for part in err["loc"]], "type": err["type"], "msg": message})
    return details


def register_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError):
        return error_response(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError):
        return error_response(422, "validation_error", "Request validation failed",
                              _safe_validation_details(exc))

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException):
        code, message = _HTTP_CODES.get(exc.status_code, ("http_error", "Request failed"))
        return error_response(exc.status_code, code, message)

    @app.exception_handler(SQLAlchemyError)
    async def handle_database_error(request: Request, exc: SQLAlchemyError):
        logger.error("database error on %s %s", request.method, request.url.path, exc_info=exc)
        if isinstance(exc, (OperationalError, InterfaceError)):
            return error_response(503, "database_error", "The database is temporarily unavailable")
        return error_response(500, "internal_error", "Internal server error")

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception):
        logger.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        return error_response(500, "internal_error", "Internal server error")
