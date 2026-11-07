"""Adapter settings: environment only, no database variables, secret never printed."""
import pytest
from pydantic import ValidationError

from integrations.config import IntegrationSettings, load_settings

KEY = "k3y-for-tests-0123456789abcdef"


def make(**overrides):
    values = {"ingest_api_key": KEY, **overrides}
    return IntegrationSettings(_env_file=None, **values)


def test_defaults_point_at_localhost():
    settings = make()
    assert settings.threatscope_api_url == "http://127.0.0.1:8000"
    assert settings.threatscope_timeout_seconds == 10


def test_api_key_is_required(monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    with pytest.raises(ValidationError):
        IntegrationSettings(_env_file=None)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_api_key_is_refused(blank):
    with pytest.raises(ValidationError):
        make(ingest_api_key=blank)


def test_api_key_never_appears_in_repr_str_or_errors():
    settings = make()
    assert KEY not in repr(settings)
    assert KEY not in str(settings)
    assert KEY not in str(settings.model_dump())
    with pytest.raises(ValidationError) as caught:
        make(threatscope_api_url="ftp://bad")
    assert KEY not in str(caught.value)


def test_trailing_slash_is_removed():
    assert make(threatscope_api_url="http://localhost:8000/").threatscope_api_url == "http://localhost:8000"


@pytest.mark.parametrize("url", [
    "ftp://localhost:8000",             # wrong scheme
    "localhost:8000",                   # no scheme
    "http://",                          # no host
    "http://user:secret@localhost:8000",  # credentials in a URL leak into logs
    "http://localhost:8000/?key=1",     # query string
    "http://localhost:8000/#frag",      # fragment
    "http://localhost:8000/api",        # path prefix: client builds its own paths
])
def test_bad_api_urls_are_refused(url):
    with pytest.raises(ValidationError):
        make(threatscope_api_url=url)


@pytest.mark.parametrize("timeout", [0, -1, 121])
def test_timeout_must_be_between_zero_and_two_minutes(timeout):
    with pytest.raises(ValidationError):
        make(threatscope_timeout_seconds=timeout)


def test_load_settings_reads_environment(monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", KEY)
    monkeypatch.setenv("THREATSCOPE_API_URL", "http://127.0.0.1:9000")
    monkeypatch.setenv("THREATSCOPE_TIMEOUT_SECONDS", "2.5")
    settings = load_settings()
    assert settings.ingest_api_key.get_secret_value() == KEY
    assert settings.threatscope_api_url == "http://127.0.0.1:9000"
    assert settings.threatscope_timeout_seconds == 2.5
