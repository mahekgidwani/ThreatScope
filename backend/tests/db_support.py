"""Engine builders for the database tests (SQLite for speed, PostgreSQL for truth)."""
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.db import Base, init_db, make_engine
from tests.db_guard import assert_safe_test_database


def build_sqlite_engine() -> Engine:
    """In-memory SQLite shared by every connection of this engine, with foreign keys enforced."""
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    return engine


def build_postgres_engine(settings: Settings) -> Engine:
    """Engine for the `<POSTGRES_DB>_test` database, created on demand.

    The guard runs FIRST, before any connection or engine exists.
    """
    dev_db = settings.postgres_db
    test_url = settings.sqlalchemy_url.set(database=f"{dev_db}_test")
    assert_safe_test_database(test_url, dev_db)

    admin = create_engine(settings.sqlalchemy_url.set(database="postgres"),
                          isolation_level="AUTOCOMMIT", connect_args={"connect_timeout": 3})
    try:
        with admin.connect() as conn:
            exists = conn.execute(text("SELECT 1 FROM pg_database WHERE datname = :n"),
                                  {"n": test_url.database}).scalar()
            if not exists:  # the name was validated by the guard, so quoting it is safe
                conn.execute(text(f'CREATE DATABASE "{test_url.database}"'))
    except OperationalError as exc:
        pytest.fail("PostgreSQL is mandatory for these tests but is not reachable "
                    f"({type(exc.orig).__name__}). Start it with: docker compose up -d db",
                    pytrace=False)
    finally:
        admin.dispose()
    return make_engine(test_url)


def reset_schema(engine: Engine, dev_db_name: str | None = None) -> None:
    """Drop and recreate all tables. On PostgreSQL this is allowed only on a *_test database."""
    if engine.dialect.name == "postgresql":
        assert_safe_test_database(engine.url, dev_db_name or "")
    Base.metadata.drop_all(engine)
    init_db(engine)
