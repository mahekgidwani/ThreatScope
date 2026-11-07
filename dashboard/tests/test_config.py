import pytest
from pydantic import ValidationError

from ts_dashboard.config import DashboardSettings


def test_defaults_point_at_the_local_api(monkeypatch):
    monkeypatch.delenv("THREATSCOPE_API_URL", raising=False)
    monkeypatch.delenv("THREATSCOPE_TIMEOUT_SECONDS", raising=False)
    settings = DashboardSettings(_env_file=None)
    assert settings.threatscope_api_url == "http://127.0.0.1:8000"
    assert settings.threatscope_timeout_seconds == 10


def test_environment_overrides(monkeypatch):
    monkeypatch.setenv("THREATSCOPE_API_URL", "https://api.example:9000/")
    monkeypatch.setenv("THREATSCOPE_TIMEOUT_SECONDS", "3")
    settings = DashboardSettings(_env_file=None)
    assert settings.threatscope_api_url == "https://api.example:9000"
    assert settings.threatscope_timeout_seconds == 3


@pytest.mark.parametrize("url", [
    "ftp://host", "host:8000", "http://", "http://user:pw@host", "http://host/path", "http://host?x=1",
    "http://host#frag", "http://host:notaport", "http://host:99999",
])
def test_bad_urls_are_rejected(url):
    with pytest.raises(ValidationError):
        DashboardSettings(threatscope_api_url=url, _env_file=None)


@pytest.mark.parametrize("seconds", [0, -1, 121])
def test_timeout_must_be_sensible(seconds):
    with pytest.raises(ValidationError):
        DashboardSettings(threatscope_timeout_seconds=seconds, _env_file=None)


def test_validation_error_never_echoes_the_bad_value():
    with pytest.raises(ValidationError) as caught:
        DashboardSettings(threatscope_api_url="http://user:supersecret@host", _env_file=None)
    assert "supersecret" not in str(caught.value)


KEY = "0123456789abcdefSECRETKEY"


def test_the_api_key_is_optional_and_off_by_default(monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    assert DashboardSettings(_env_file=None).ingest_api_key is None


def test_the_api_key_is_read_from_the_environment_or_env_file_and_never_printed(monkeypatch, tmp_path):
    monkeypatch.setenv("INGEST_API_KEY", KEY)
    from_env = DashboardSettings(_env_file=None)
    assert from_env.ingest_api_key.get_secret_value() == KEY
    assert KEY not in repr(from_env) and KEY not in str(from_env) and KEY not in str(from_env.model_dump()) and KEY not in from_env.model_dump_json()
    monkeypatch.delenv("INGEST_API_KEY")
    env_file = tmp_path / ".env"
    env_file.write_text(f"INGEST_API_KEY={KEY}\nPOSTGRES_PASSWORD=hunter2hunter2\n")
    from_file = DashboardSettings(_env_file=env_file)
    assert from_file.ingest_api_key.get_secret_value() == KEY
    assert "hunter2" not in repr(from_file) + str(from_file.model_dump())          # other secrets in .env are ignored


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_key_means_read_only(monkeypatch, blank):
    monkeypatch.setenv("INGEST_API_KEY", blank)
    assert DashboardSettings(_env_file=None).ingest_api_key is None


def test_only_these_settings_exist():
    assert set(DashboardSettings.model_fields) == {"threatscope_api_url", "threatscope_timeout_seconds", "ingest_api_key"}
