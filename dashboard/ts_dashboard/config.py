"""Dashboard settings: where the API is and how long to wait.

Same variable names as the Phase 3 adapters (THREATSCOPE_API_URL, THREATSCOPE_TIMEOUT_SECONDS).
There is deliberately NO API-key setting: every GET endpoint the dashboard uses is open, only
POST /api/v1/events needs the key, and the dashboard never writes. A dashboard that does not
hold the key cannot leak it. `.env` is read, but its other keys (database password, ingest key) are ignored.
"""
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DashboardSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),   # dashboard/ when run from there, or the project root
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    threatscope_api_url: str = "http://127.0.0.1:8000"
    threatscope_timeout_seconds: float = Field(default=10, gt=0, le=120)

    @field_validator("threatscope_api_url")
    @classmethod
    def _plain_base_url(cls, value: str) -> str:
        """Only scheme://host[:port]: credentials would leak into logs, and the client adds the paths."""
        try:
            parts = urlsplit(value)
            parts.port  # noqa: B018 - accessing it validates the port number
        except ValueError:
            raise ValueError("THREATSCOPE_API_URL is malformed") from None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("THREATSCOPE_API_URL must look like http://host:port")
        if parts.username is not None or parts.password is not None:
            raise ValueError("THREATSCOPE_API_URL must not contain credentials")
        if parts.query or parts.fragment or parts.path not in ("", "/"):
            raise ValueError("THREATSCOPE_API_URL must not contain a path, query or fragment")
        return f"{parts.scheme}://{parts.netloc}"


def load_settings() -> DashboardSettings:
    """Raises pydantic.ValidationError (which never echoes the offending value) if configuration is invalid."""
    return DashboardSettings()
