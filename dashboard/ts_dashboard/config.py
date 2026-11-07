"""Dashboard settings: where the API is and how long to wait.

Same variable names as the Phase 3 adapters (THREATSCOPE_API_URL, THREATSCOPE_TIMEOUT_SECONDS).
Reading needs no key: every GET endpoint is open. Only the incident WRITES (create, change status / notes / events)
need the API key, so `INGEST_API_KEY` is optional here: without it the dashboard is read-only. The key is a SecretStr,
is sent only as the X-API-Key header on those write calls, and is never shown or logged. `.env` is read, but its other
keys (database password, ...) are ignored.
"""
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
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
    ingest_api_key: SecretStr | None = None   # optional: enables incident editing

    @field_validator("ingest_api_key")
    @classmethod
    def _blank_key_means_none(cls, value: SecretStr | None) -> SecretStr | None:
        return value if value is not None and value.get_secret_value().strip() else None

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
