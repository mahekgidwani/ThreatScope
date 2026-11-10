"""The command-line tool: analyse paths, submit through the shared client, report plainly."""
import json
import lzma

import httpx
import pytest

from integrations.analyse_file import main
from integrations.client import ThreatScopeClient
from integrations.config import IntegrationSettings
from tests.integrations.samples import write

KEY = "k3y-for-tests-0123456789abcdef"
SECRET_CONTENT = "SECRET-CONTENT-123 top secret body"


def fake_client(handler):
    http = httpx.Client(base_url="http://testserver", transport=httpx.MockTransport(handler))
    return ThreatScopeClient(IntegrationSettings(_env_file=None, ingest_api_key=KEY), http_client=http)


def created(request):
    return httpx.Response(201, json={"id": "11111111-1111-1111-1111-111111111111"})


def duplicate(request):
    return httpx.Response(409, json={"error": {"code": "duplicate_event", "message": "m",
                                               "details": {"existing_id": "abc-1"}}})


def run(argv, capsys, **kwargs):
    code = main(argv, **kwargs)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_stored_file_is_reported(tmp_path, capsys):
    path = write(tmp_path, "a.txt", SECRET_CONTENT)
    code, out, err = run([str(path)], capsys, client=fake_client(created))
    assert code == 0
    assert "a.txt" in out and "stored" in out and "11111111-1111-1111-1111-111111111111" in out


def test_duplicate_is_reported_as_already_recorded_and_is_success(tmp_path, capsys):
    code, out, _ = run([str(write(tmp_path, "a.txt", "hi"))], capsys, client=fake_client(duplicate))
    assert code == 0 and "already" in out and "abc-1" in out


def test_output_never_contains_file_content_or_the_key(tmp_path, capsys):
    path = write(tmp_path, "a.txt", SECRET_CONTENT)
    _, out, err = run([str(path)], capsys, client=fake_client(created))
    for text in (out, err):
        assert "SECRET-CONTENT" not in text
        assert KEY not in text


def test_dry_run_prints_the_event_and_sends_nothing(tmp_path, capsys):
    path = write(tmp_path, "a.txt", SECRET_CONTENT)

    def must_not_be_called(request):
        raise AssertionError("dry run must not call the API")

    code, out, _ = run([str(path), "--dry-run"], capsys, client=fake_client(must_not_be_called))
    event = json.loads(out)
    assert code == 0
    assert event["source"] == "file" and event["metadata"]["file_name"] == "a.txt"
    assert "SECRET-CONTENT" not in out


def test_dry_run_needs_no_api_key(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)

    def no_settings():
        return IntegrationSettings(_env_file=None)

    code, out, _ = run([str(write(tmp_path, "a.txt", "hi")), "--dry-run"], capsys, settings_loader=no_settings)
    assert code == 0 and json.loads(out)["source"] == "file"


def test_missing_api_key_is_a_clear_message_without_a_traceback(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)

    def no_settings():
        return IntegrationSettings(_env_file=None)

    code, out, err = run([str(write(tmp_path, "a.txt", "hi"))], capsys, settings_loader=no_settings)
    assert code == 2
    assert "INGEST_API_KEY" in err and "Traceback" not in err


def test_problem_files_are_reported_and_the_rest_still_processed(tmp_path, capsys):
    good = write(tmp_path, "good.txt", "hello")
    empty = write(tmp_path, "empty.txt", b"")
    big = write(tmp_path, "big.txt", b"x" * 2000)
    missing = tmp_path / "missing.txt"
    code, out, err = run([str(empty), str(big), str(missing), str(tmp_path), str(good),
                          "--max-bytes", "1000"], capsys, client=fake_client(created))
    assert code == 1
    assert "good.txt" in out and "stored" in out
    for word in ("empty", "too large", "not found", "not a file"):
        assert word in err.lower()


def test_one_bad_file_does_not_stop_the_batch(tmp_path, capsys, monkeypatch):
    from integrations import analyse_file as cli
    real = cli.analyse_file
    bad, good = write(tmp_path, "bad.docx", "SECRET-IN-MESSAGE"), write(tmp_path, "good.txt", "hello")

    def flaky(path, **kwargs):
        if str(path) == str(bad):
            raise lzma.LZMAError("SECRET-IN-MESSAGE")
        return real(path, **kwargs)

    monkeypatch.setattr(cli, "analyse_file", flaky)
    code, out, err = run([str(bad), str(good)], capsys, client=fake_client(created))
    assert code == 1
    assert "good.txt" in out and "stored" in out
    assert "bad.docx: analysis failed - LZMAError" in err
    assert "SECRET-IN-MESSAGE" not in err and "Traceback" not in err


def test_api_rejection_is_reported_and_exit_code_is_1(tmp_path, capsys):
    def reject(request):
        return httpx.Response(422, json={"error": {"code": "validation_error", "message": "bad",
                                                   "details": []}})

    code, _, err = run([str(write(tmp_path, "a.txt", "hi"))], capsys, client=fake_client(reject))
    assert code == 1 and "422" in err


def test_bad_key_stops_after_the_first_file(tmp_path, capsys):
    calls = []

    def unauthorized(request):
        calls.append(1)
        return httpx.Response(401, json={"error": {"code": "unauthorized", "message": "no", "details": {}}})

    files = [str(write(tmp_path, f"{i}.txt", f"file {i}")) for i in range(3)]
    code, _, err = run(files, capsys, client=fake_client(unauthorized))
    assert code == 1 and len(calls) == 1 and "API key" in err


def test_unreachable_api_is_reported(tmp_path, capsys):
    def down(request):
        raise httpx.ConnectError("refused")

    code, _, err = run([str(write(tmp_path, "a.txt", "hi"))], capsys, client=fake_client(down))
    assert code == 1 and "could not reach" in err


def test_no_paths_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2
