"""Tests for app.config. Only fake, safe values are used here."""
import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy.engine import URL, make_url

from app.config import Settings, get_settings

GOOD_KEY = "Zx9-test-key-0123456789abcdef"  # fake; 29 chars; many distinct characters
BASE = dict(
    ingest_api_key=GOOD_KEY,
    postgres_user="ts_user",
    postgres_password="fake-db-pass",
    postgres_db="ts_db",
)
ENV_NAMES = [
    "APP_ENV", "LOG_LEVEL", "INGEST_API_KEY", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "POSTGRES_DB", "POSTGRES_HOST", "POSTGRES_PORT", "MAX_METADATA_BYTES", "DATABASE_URL",
]


def make(**over) -> Settings:
    """Build Settings from explicit values only (ignores any .env file)."""
    return Settings(_env_file=None, **{**BASE, **over})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remove every setting from the environment so each test is deterministic."""
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---- valid loading -------------------------------------------------------------

def test_valid_settings_from_arguments_and_defaults():
    s = make()
    assert isinstance(s.ingest_api_key, SecretStr)
    assert s.ingest_api_key.get_secret_value() == GOOD_KEY
    assert (s.app_env, s.log_level) == ("dev", "INFO")
    assert (s.postgres_host, s.postgres_port) == ("db", 5432)
    assert s.max_metadata_bytes == 65536


def test_loads_from_env_file_and_ignores_extra_keys(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "APP_ENV=prod\nLOG_LEVEL=debug\n"
        f"INGEST_API_KEY={GOOD_KEY}\n"
        "POSTGRES_USER=file_user\nPOSTGRES_PASSWORD=file-pass-fake\nPOSTGRES_DB=file_db\n"
        "POSTGRES_HOST=localhost\nPOSTGRES_PORT=5433\nMAX_METADATA_BYTES=2048\n"
        "POSTGRES_HOST_PORT=5999\n",  # docker-compose-only key: must be ignored, not an error
        encoding="utf-8",
    )
    s = Settings(_env_file=env_file)
    assert s.app_env == "prod"
    assert s.log_level == "DEBUG"  # normalised to upper case
    assert s.ingest_api_key.get_secret_value() == GOOD_KEY
    assert (s.postgres_user, s.postgres_db, s.postgres_host, s.postgres_port) == (
        "file_user", "file_db", "localhost", 5433)
    assert s.max_metadata_bytes == 2048


def test_loads_from_environment_variables(monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", GOOD_KEY)
    monkeypatch.setenv("POSTGRES_USER", "env_user")
    monkeypatch.setenv("POSTGRES_PASSWORD", "env-pass-fake")
    monkeypatch.setenv("POSTGRES_DB", "env_db")
    s = Settings(_env_file=None)
    assert s.postgres_user == "env_user"
    assert s.ingest_api_key.get_secret_value() == GOOD_KEY


def test_get_settings_is_cached(monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", GOOD_KEY)
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "fake-db-pass")
    monkeypatch.setenv("POSTGRES_DB", "d")
    assert get_settings() is get_settings()


# ---- API key rules -------------------------------------------------------------

def test_missing_key_rejected():
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None, postgres_user="u", postgres_password="fake-db-pass", postgres_db="d")
    assert "ingest_api_key" in str(exc.value)


@pytest.mark.parametrize("key", ["", "short", "a1b2c3d4e5f6g7h"])  # last one = 15 chars
def test_short_key_rejected(key):
    with pytest.raises(ValidationError):
        make(ingest_api_key=key)


def test_minimum_length_boundary_is_16():
    assert make(ingest_api_key="0123456789abcdef").ingest_api_key.get_secret_value()
    with pytest.raises(ValidationError):
        make(ingest_api_key="0123456789abcde")  # 15


@pytest.mark.parametrize("key", [
    "change-me", "CHANGE-ME", "changeme", "change-me-change-me", "Change-Me-9x8y7z6w5v",
    "your-api-key-goes-here-1", "my-password-9x8y7z6w5v",
])
def test_placeholder_keys_rejected(key):
    with pytest.raises(ValidationError):
        make(ingest_api_key=key)


@pytest.mark.parametrize("key", ["a" * 32, "ab" * 16, "0000000000000000", "abcabc" * 5])
def test_low_variety_keys_rejected(key):
    with pytest.raises(ValidationError):
        make(ingest_api_key=key)


@pytest.mark.parametrize("key", [f" {GOOD_KEY}", f"{GOOD_KEY}\n", f"{GOOD_KEY} "])
def test_key_with_surrounding_whitespace_rejected(key):
    with pytest.raises(ValidationError):
        make(ingest_api_key=key)


def test_rejection_message_does_not_echo_the_key():
    weak = "shortKey1"
    with pytest.raises(ValidationError) as exc:
        make(ingest_api_key=weak)
    assert weak not in str(exc.value)
    assert weak not in repr(exc.value)


# ---- other validation ----------------------------------------------------------

@pytest.mark.parametrize("over", [
    {"postgres_port": 0}, {"postgres_port": 70000}, {"postgres_port": "abc"},
    {"app_env": "staging"}, {"log_level": "LOUD"}, {"max_metadata_bytes": 0},
    {"postgres_password": ""}, {"postgres_user": ""}, {"postgres_db": ""},
])
def test_invalid_values_rejected(over):
    with pytest.raises(ValidationError):
        make(**over)


def test_log_level_is_normalised():
    assert make(log_level="warning").log_level == "WARNING"


# ---- secret redaction ----------------------------------------------------------

def test_secrets_never_appear_in_representations():
    db_url_password = "dbpass-FAKE-77"
    s = make(database_url=f"postgresql+psycopg://u:{db_url_password}@h:5432/d")
    outputs = [
        repr(s), str(s), f"{s}", f"{s!r}", "%s" % s,
        s.model_dump_json(), str(s.model_dump()), str(s.model_dump(mode="json")),
        repr(s.ingest_api_key), str(s.postgres_password), repr(s.database_url),
    ]
    text = "\n".join(outputs)
    for secret in (GOOD_KEY, "fake-db-pass", db_url_password):
        assert secret not in text
    assert "**********" in text


# ---- database URL --------------------------------------------------------------

def test_url_built_with_url_create_handles_special_characters():
    password = "p@ss:/w?rd#%&= +x"
    user = "us@er:name"
    s = make(postgres_user=user, postgres_password=password, postgres_db="db name",
             postgres_host="db", postgres_port=5433)
    url = s.sqlalchemy_url
    assert isinstance(url, URL)
    assert url.drivername == "postgresql+psycopg"
    assert (url.username, url.password, url.database, url.host, url.port) == (
        user, password, "db name", "db", 5433)
    # The rendered form must be correctly escaped: parsing it gives the same parts back.
    parsed = make_url(url.render_as_string(hide_password=False))
    assert (parsed.username, parsed.password, parsed.database) == (user, password, "db name")
    # ...and the URL object never prints its password.
    assert password not in str(url)
    assert password not in repr(url)


def test_explicit_database_url_wins_and_is_decoded():
    assert make(database_url="sqlite://").sqlalchemy_url.drivername == "sqlite"
    url = make(database_url="postgresql+psycopg://u:p%40ss@h:5432/d").sqlalchemy_url
    assert url.password == "p@ss"


def test_malformed_database_url_rejected_without_echo():
    bad = "not-a-url-with-secret-TOKEN123"
    with pytest.raises(ValidationError) as exc:
        make(database_url=bad)
    assert bad not in str(exc.value)


def test_safe_database_url_hides_the_password():
    s = make(postgres_password="pw-FAKE-123")
    assert "pw-FAKE-123" not in s.safe_database_url
    assert "***" in s.safe_database_url
    assert "ts_user" in s.safe_database_url
