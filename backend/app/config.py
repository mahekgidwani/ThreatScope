"""Application settings, loaded from environment variables / the project's .env file.

Secrets (API key, database password, optional DATABASE_URL) are `SecretStr`, so they
print as '**********' in repr(), str(), model_dump() and JSON. Use `.get_secret_value()`
only at the exact place a secret is needed.
"""
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

MIN_API_KEY_LENGTH = 16
MIN_DISTINCT_KEY_CHARS = 6  # rejects keys like "aaaaaaaaaaaaaaaa" or "abababababababab"
_PLACEHOLDER_FRAGMENTS = ("change-me", "changeme", "your-api-key", "your_api_key", "password")
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class Settings(BaseSettings):
    """All configuration for the backend. Environment variable names match `.env.example`."""

    model_config = SettingsConfigDict(
        # ".env" when run from the project root, "../.env" when run from backend/.
        # Real environment variables always win over file values.
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",              # .env also holds docker-compose-only keys (POSTGRES_HOST_PORT)
        hide_input_in_errors=True,   # validation errors must never echo secret values
    )

    app_env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"

    ingest_api_key: SecretStr

    postgres_user: str = Field(min_length=1)
    postgres_password: SecretStr = Field(min_length=1)
    postgres_db: str = Field(min_length=1)
    postgres_host: str = Field(default="db", min_length=1)
    postgres_port: int = Field(default=5432, ge=1, le=65535)

    max_metadata_bytes: int = Field(default=65536, gt=0)

    # Optional full URL; when set it replaces the POSTGRES_* parts. Treated as a secret.
    database_url: SecretStr | None = None

    @field_validator("ingest_api_key")
    @classmethod
    def _check_api_key(cls, value: SecretStr) -> SecretStr:
        key = value.get_secret_value()
        # Messages below deliberately never include the key itself.
        if key != key.strip():
            raise ValueError("API key must not start or end with whitespace")
        if len(key) < MIN_API_KEY_LENGTH:
            raise ValueError(f"API key must be at least {MIN_API_KEY_LENGTH} characters long")
        lowered = key.casefold()
        if any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS):
            raise ValueError("API key looks like a placeholder; generate a random one")
        if len(set(key)) < MIN_DISTINCT_KEY_CHARS:
            raise ValueError("API key is too repetitive; generate a random one")
        return value

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {', '.join(_LOG_LEVELS)}")
        return level

    @field_validator("database_url")
    @classmethod
    def _check_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            try:
                make_url(value.get_secret_value())
            except Exception:  # noqa: BLE001 - never let the URL text reach an error message
                raise ValueError("DATABASE_URL is not a valid SQLAlchemy URL") from None
        return value

    @property
    def sqlalchemy_url(self) -> URL:
        """Database URL for SQLAlchemy.

        Built with `URL.create`, which keeps user, password, host and database as separate
        values and escapes special characters (@ : / ? # % space) when the URL is rendered.
        Never build this by joining strings.
        """
        if self.database_url is not None:
            return make_url(self.database_url.get_secret_value())
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @property
    def safe_database_url(self) -> str:
        """URL text with the password replaced by '***' - the only form that may be logged."""
        return self.sqlalchemy_url.render_as_string(hide_password=True)


@lru_cache
def get_settings() -> Settings:
    """Load settings once and reuse them. Raises ValidationError if configuration is invalid."""
    return Settings()
