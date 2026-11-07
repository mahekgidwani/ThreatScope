"""Application factory and entry point (`uvicorn app.main:app`)."""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app import db as db_module
from app.api import events, incidents, indicators
from app.config import get_settings
from app.errors import register_handlers
from app.logging_config import configure_logging

access_log = logging.getLogger("app.access")


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

    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        # Method, path and status only: never headers, query strings or bodies (they may hold secrets).
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            access_log.info("%s %s %s %.1fms", request.method, request.url.path, status,
                            (time.perf_counter() - started) * 1000)

    application.include_router(events.router)
    application.include_router(indicators.router)
    application.include_router(incidents.router)
    return application


app = create_app()
