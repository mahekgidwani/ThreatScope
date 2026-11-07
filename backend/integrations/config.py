"""Settings for adapters: where the API is, which key to use, how long to wait.

Read from environment variables (and the project's .env file), like the backend. Adapters
do NOT need the database settings. The key is a `SecretStr`, so it never shows in repr/str.
"""
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class IntegrationSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),   # project root, or backend/ when run from there
        env_file_encoding="utf-8",
        extra="ignore",                 # .env holds many backend-only keys
        hide_input_in_errors=True,      # validation errors must never echo the key or URL
    )

    ingest_api_key: SecretStr           # same variable the API reads (INGEST_API_KEY)
    threatscope_api_url: str = "http://127.0.0.1:8000"
    threatscope_timeout_seconds: float = Field(default=10, gt=0, le=120)

    @field_validator("ingest_api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("INGEST_API_KEY must not be blank")
        return value

    @field_validator("threatscope_api_url")
    @classmethod
    def _plain_base_url(cls, value: str) -> str:
        """Only scheme://host[:port]. No credentials (they leak into logs), query or path
        (the client adds its own paths)."""
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


def load_settings() -> IntegrationSettings:
    """Raises pydantic.ValidationError (without secret values) if configuration is invalid."""
    return IntegrationSettings()
