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


def test_the_dashboard_holds_no_api_key(monkeypatch, tmp_path):
    monkeypatch.setenv("INGEST_API_KEY", "0123456789abcdef0123456789abcdef")
    env_file = tmp_path / ".env"
    env_file.write_text("INGEST_API_KEY=abcdefabcdefabcdef12\nPOSTGRES_PASSWORD=hunter2hunter2\n")
    settings = DashboardSettings(_env_file=env_file)
    dumped = repr(settings) + str(settings.model_dump())
    assert "abcdefabcdef" not in dumped and "hunter2" not in dumped and "0123456789abcdef" not in dumped
    assert set(DashboardSettings.model_fields) == {"threatscope_api_url", "threatscope_timeout_seconds"}
