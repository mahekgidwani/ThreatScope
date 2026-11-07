"""Dependencies shared by the routers."""
import hmac

from fastapi import Header
from sqlalchemy.engine import Engine

from app import db as db_module
from app.config import get_settings
from app.errors import AuthError


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Protect write endpoints. The key comes from the environment, is compared in constant
    time, and is never logged or returned."""
    expected = get_settings().ingest_api_key.get_secret_value().encode("utf-8")
    provided = (x_api_key or "").encode("utf-8")
    if not x_api_key or not hmac.compare_digest(provided, expected):
        raise AuthError()


def get_engine_dep() -> Engine:
    """The engine behind the sessions; a separate dependency so /health (Task 9) can be tested."""
    return db_module.get_engine()
