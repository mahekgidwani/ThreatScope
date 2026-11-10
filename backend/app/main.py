"""Application factory and entry point (`uvicorn app.main:app`)."""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app import db as db_module
from app.api import events, health, incidents, indicators
from app.config import get_settings
from app.errors import error_response, register_handlers
from app.logging_config import configure_logging

access_log = logging.getLogger("app.access")

# A legitimate event is far smaller (metadata alone is capped at 64 KiB). This is a fixed constant, not a setting:
# json.dumps escapes a 4-byte character to 12 bytes on the wire, so it must stay above ~3x MAX_METADATA_BYTES
# or legitimate adapter events start getting 413 if MAX_METADATA_BYTES is raised.
MAX_REQUEST_BYTES = 256 * 1024


def create_app(run_startup: bool = True) -> FastAPI:
    """Build the application. `run_startup=False` skips settings loading, logging setup and
    table creation (tests supply their own database)."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if run_startup:
            settings = get_settings()  # raises (and stops the app) if configuration is invalid
            configure_logging(settings.log_level, secrets=[
                settings.ingest_api_key.get_secret_value(),
                settings.postgres_password.get_secret_value(),
                settings.database_url.get_secret_value() if settings.database_url else None,
            ])
            db_module.init_db(db_module.get_engine())
            logging.getLogger(__name__).info(
                "ThreatScope API started (env=%s, database=%s)", settings.app_env, settings.safe_database_url)
        yield

    application = FastAPI(title="ThreatScope API", version="0.2.0", lifespan=lifespan)
    register_handlers(application)

    # Added before log_requests so it sits inside it: a rejected request is still logged.
    @application.middleware("http")
    async def limit_request_size(request: Request, call_next):
        # Runs before auth and before the body is read. shortcut: chunked bodies without a
        # Content-Length are not capped; put a reverse proxy in front if the API is ever exposed.
        try:
            too_big = int(request.headers.get("content-length", "0")) > MAX_REQUEST_BYTES
        except ValueError:
            too_big = False   # non-numeric: the HTTP server rejects it itself; never crash here
        if too_big:
            return error_response(413, "payload_too_large", "Request body is too large")
        return await call_next(request)

    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        # Method, path and status only: never headers, query strings or bodies (they may hold secrets).
        # The decoded path is logged with %r so control characters (e.g. %0A) cannot forge log lines.
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            access_log.info("%s %r %s %.1fms", request.method, request.scope["path"], status,
                            (time.perf_counter() - started) * 1000)

    application.include_router(health.router)
    application.include_router(events.router)
    application.include_router(indicators.router)
    application.include_router(incidents.router)
    return application


app = create_app()
