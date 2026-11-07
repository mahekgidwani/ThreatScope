"""Database plumbing: naming convention, engine, sessions, schema creation, health check.

This module is the only place that creates tables (`init_db`). When the project later
moves to Alembic, `init_db` is the one function to replace with `alembic upgrade head`.
"""
import logging
import time
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session

from app.config import get_settings

logger = logging.getLogger(__name__)

# Predictable constraint/index names. Without them each database invents its own names,
# which makes later migrations (Alembic) awkward.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Parent of every table class. One shared MetaData with the naming convention."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def make_engine(url: str | URL) -> Engine:
    """Create an engine. PostgreSQL gets a short connect timeout so a dead database fails fast."""
    url = make_url(url) if isinstance(url, str) else url
    # hide_parameters: a failed statement's error text must not contain the event data (description,
    # metadata, ...) that was being stored.
    options: dict = {"pool_pre_ping": True, "hide_parameters": True}
    if url.get_backend_name() == "postgresql":
        options["connect_args"] = {"connect_timeout": 2}
    return create_engine(url, **options)


@lru_cache
def get_engine() -> Engine:
    """The application's engine, built once from the settings."""
    return make_engine(get_settings().sqlalchemy_url)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request.

    Committing is the caller's job. Anything uncommitted is rolled back if an error occurs.
    """
    session = Session(get_engine(), expire_on_commit=False)
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(engine: Engine) -> None:
    """Create any missing tables (never alters or drops existing ones)."""
    import app.models  # noqa: F401  - importing registers every table on Base.metadata

    Base.metadata.create_all(engine)


def check_db(engine: Engine) -> tuple[bool, float | None]:
    """Return (reachable, latency in ms). Never raises; the log gets the error type only."""
    started = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - a health check must never raise
        logger.warning("database check failed (%s)", type(exc).__name__)
        return False, None
    return True, round((time.perf_counter() - started) * 1000, 2)
