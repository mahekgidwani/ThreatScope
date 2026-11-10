"""The ModSecurity log adapter: read a JSON-lines audit log, remember where it stopped, send events."""
import json

import httpx
import pytest

from integrations.config import IntegrationSettings
from integrations.modsec_adapter import main
from integrations.client import ThreatScopeClient
from app.schemas.event import EventIn
from tests.conftest import TEST_API_KEY
from tests.integrations.fakes import KEY, created, duplicate, error_reply, fake_client
from tests.integrations.modsec_samples import CANARY, SQLI, line, record
from tests.integrations.samples import write


def run(argv, capsys, **kwargs):
    code = main(argv, **kwargs)
    out = capsys.readouterr()
    return code, out.out, out.err


class Recorder:
    """A fake API that remembers which transaction ids it was sent."""

    def __init__(self, reply=created):
        self.reply, self.ids = reply, []

    def __call__(self, request):
        self.ids.append(json.loads(request.content)["external_event_id"])
        return self.reply(request)


def log_of(*records):
    return "\n".join(line(r) for r in records) + "\n"


def two_attacks():
    return [record(transaction_id="T1"), record(transaction_id="T2", remote="198.51.100.9", messages=SQLI)]


# ---- basic reading ---------------------------------------------------------------------------

def test_attack_records_are_sent_and_summarised(tmp_path, capsys):
    log = write(tmp_path, "audit.log", log_of(*two_attacks()))
    seen = Recorder()
    code, out, _ = run([str(log)], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 2
    assert "read 2 record(s)" in out and "stored 2" in out


def test_each_problem_line_is_counted_and_the_rest_still_processed(tmp_path, capsys):
    bad_ip, bad_time = record(transaction_id="B1", remote="999.1.1.1"), record(transaction_id="B2", time="nope")
    text = "\n".join([
        line(record(transaction_id="OK1")),
        "",                                            # blank
        "this is not json",                            # malformed
        "[1, 2, 3]",                                   # JSON but not an object
        line(record(transaction_id="NOHIT", messages=[])),   # clean request, no rule hits
        line(bad_ip), line(bad_time),
        "x" * 2_000_000,                               # absurdly long line
        '{"unterminated": ',                           # broken JSON
        line(record(transaction_id="OK2", remote="198.51.100.4")),
    ]) + "\n"
    seen = Recorder()
    code, out, _ = run([str(write(tmp_path, "audit.log", text))], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 2
    assert "stored 2" in out
    assert "no rule hits 1" in out
    assert "invalid 6" in out    # not json, not an object, bad ip, bad time, over-long line, broken json


def test_summary_numbers_add_up(tmp_path, capsys):
    text = "\n".join(["not json", line(record(messages=[])), "x" * 2_000_000, line(record(transaction_id="A"))]) + "\n"
    _, out, _ = run([str(write(tmp_path, "a.log", text))], capsys, client=fake_client(created))
    assert "read 4 record(s)" in out and "stored 1" in out and "no rule hits 1" in out and "invalid 2" in out


def test_duplicates_are_counted_not_failed(tmp_path, capsys):
    log = write(tmp_path, "audit.log", log_of(*two_attacks()))
    code, out, _ = run([str(log)], capsys, client=fake_client(duplicate))
    assert code == 0 and "already recorded 2" in out


def test_repeated_log_entries_use_the_same_event_id(tmp_path, capsys):
    same = record(transaction_id="SAME")
    seen = Recorder()
    run([str(write(tmp_path, "a.log", log_of(same, same)))], capsys, client=fake_client(seen))
    assert len(seen.ids) == 2 and seen.ids[0] == seen.ids[1]


def test_windows_line_endings_and_utf8_bom(tmp_path, capsys):
    data = b"\xef\xbb\xbf" + log_of(*two_attacks()).replace("\n", "\r\n").encode("utf-8")
    seen = Recorder()
    code, _, _ = run([str(write(tmp_path, "a.log", data))], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 2


def test_invalid_utf8_bytes_do_not_kill_the_run(tmp_path, capsys):
    data = line(record(transaction_id="A")).encode("utf-8") + b"\n\xff\xfe\x00garbage\xff\n" \
        + line(record(transaction_id="B", remote="198.51.100.4")).encode("utf-8") + b"\n"
    seen = Recorder()
    code, _, _ = run([str(write(tmp_path, "a.log", data))], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 2


def test_last_line_without_newline_is_read_if_complete(tmp_path, capsys):
    seen = Recorder()
    run([str(write(tmp_path, "a.log", line(record(transaction_id="END"))))], capsys, client=fake_client(seen))
    assert len(seen.ids) == 1


# ---- secrets never leave ---------------------------------------------------------------------

def test_no_canary_in_events_output_or_state(tmp_path, capsys):
    rec = record(transaction_id="S1", headers={"Host": "h", "Cookie": f"s={CANARY}", "User-Agent": "ua"})
    rec["request"]["body"] = f"password={CANARY}"
    log, state = write(tmp_path, "a.log", log_of(rec)), tmp_path / "state.json"
    bodies = []

    def handler(request):
        bodies.append(request.content.decode())
        return created(request)

    _, out, err = run([str(log), "--state", str(state)], capsys, client=fake_client(handler))
    assert bodies and all(CANARY not in b and KEY not in b for b in bodies)
    for text in (out, err, state.read_text()):
        assert CANARY not in text and KEY not in text


def test_events_sent_are_valid_for_the_api_schema(tmp_path, capsys):
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return created(request)

    run([str(write(tmp_path, "a.log", log_of(*two_attacks())))], capsys, client=fake_client(handler))
    for body in bodies:
        EventIn.model_validate(body)


# ---- failures -------------------------------------------------------------------------------

def test_api_rejection_is_counted_and_reading_continues(tmp_path, capsys):
    seen = Recorder(lambda r: error_reply(422, "validation_error"))
    code, out, err = run([str(write(tmp_path, "a.log", log_of(*two_attacks())))], capsys, client=fake_client(seen))
    assert code == 1 and len(seen.ids) == 2 and "failed 2" in out and "line 1" in err


def test_bad_key_stops_at_once(tmp_path, capsys):
    seen = Recorder(lambda r: error_reply(401, "unauthorized"))
    code, _, err = run([str(write(tmp_path, "a.log", log_of(*two_attacks())))], capsys, client=fake_client(seen))
    assert code == 1 and len(seen.ids) == 1 and "API key" in err


def test_unreachable_api_stops_at_once(tmp_path, capsys):
    calls = []

    def down(request):
        calls.append(1)
        raise httpx.ConnectError("refused")

    code, _, err = run([str(write(tmp_path, "a.log", log_of(*two_attacks())))], capsys, client=fake_client(down))
    assert code == 1 and len(calls) == 1 and "could not reach" in err


def test_missing_api_key_is_a_clear_message(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    code, _, err = run([str(write(tmp_path, "a.log", log_of(*two_attacks())))], capsys,
                       settings_loader=lambda: IntegrationSettings(_env_file=None))
    assert code == 2 and "INGEST_API_KEY" in err and "Traceback" not in err


def test_missing_log_file_or_directory(tmp_path, capsys):
    assert run([str(tmp_path / "nope.log")], capsys, client=fake_client(created))[0] == 2
    assert run([str(tmp_path)], capsys, client=fake_client(created))[0] == 2


# ---- incremental processing --------------------------------------------------------------------

def test_second_run_sends_only_new_lines(tmp_path, capsys):
    log, state = tmp_path / "a.log", tmp_path / "state.json"
    log.write_text(log_of(*two_attacks()))
    first = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(first))
    assert len(first.ids) == 2

    again = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(again))
    assert again.ids == []

    with log.open("a") as handle:
        handle.write(line(record(transaction_id="T3", remote="192.0.2.1")) + "\n")
    third = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(third))
    assert len(third.ids) == 1


def test_a_half_written_last_line_waits_for_the_next_run(tmp_path, capsys):
    log, state = tmp_path / "a.log", tmp_path / "state.json"
    whole = line(record(transaction_id="HALF"))
    log.write_text(line(record(transaction_id="FIRST")) + "\n" + whole[:40])
    first = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(first))
    assert len(first.ids) == 1

    log.write_text(line(record(transaction_id="FIRST")) + "\n" + whole + "\n")
    second = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(second))
    assert len(second.ids) == 1 and second.ids != first.ids


def test_a_replaced_or_truncated_log_is_read_from_the_start(tmp_path, capsys):
    log, state = tmp_path / "a.log", tmp_path / "state.json"
    log.write_text(log_of(*two_attacks()))
    run([str(log), "--state", str(state)], capsys, client=fake_client(created))

    log.write_text(log_of(record(transaction_id="NEW1", remote="192.0.2.50")))      # rotation: different, shorter
    after_rotation = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(after_rotation))
    assert len(after_rotation.ids) == 1


def test_rotation_to_a_longer_file_is_detected_by_its_different_beginning(tmp_path, capsys):
    log, state = tmp_path / "a.log", tmp_path / "state.json"
    log.write_text(log_of(record(transaction_id="OLD")))
    run([str(log), "--state", str(state)], capsys, client=fake_client(created))
    log.write_text(log_of(*[record(transaction_id=f"NEW{i}", remote=f"192.0.2.{i}") for i in range(1, 6)]))
    after = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(after))
    assert len(after.ids) == 5


def test_a_crash_inside_the_parser_is_contained(tmp_path, capsys, monkeypatch):
    import integrations.modsec_adapter as adapter
    real = adapter.build_event

    def sometimes_explodes(rec):
        if rec["transaction"]["transaction_id"] == "BOOM":
            raise RuntimeError("unexpected")
        return real(rec)

    monkeypatch.setattr(adapter, "build_event", sometimes_explodes)
    log = write(tmp_path, "a.log", log_of(record(transaction_id="BOOM"), record(transaction_id="FINE")))
    seen = Recorder()
    code, out, err = run([str(log)], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 1 and "invalid 1" in out and "RuntimeError" in err


def test_deeply_nested_json_is_just_an_invalid_line(tmp_path, capsys):
    deep = '{"a":' + "[" * 100_000 + "]" * 100_000 + "}"
    log = write(tmp_path, "a.log", "\n".join([deep, "[" * 500_000, line(record(transaction_id="OK"))]) + "\n")
    seen = Recorder()
    code, out, _ = run([str(log)], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 1 and "invalid 2" in out


def test_a_corrupt_state_file_is_ignored(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*two_attacks())), write(tmp_path, "state.json", "{{{ not json")
    seen = Recorder()
    code, _, _ = run([str(log), "--state", str(state)], capsys, client=fake_client(seen))
    assert code == 0 and len(seen.ids) == 2
    json.loads(state.read_text())                      # and it has been repaired


@pytest.mark.parametrize("bad", ['{"offset": -5}', '{"offset": "x"}', '{"offset": 99999999, "head": "zz"}', "[]", "null"])
def test_nonsense_state_values_mean_start_from_the_beginning(tmp_path, capsys, bad):
    log, state = write(tmp_path, "a.log", log_of(*two_attacks())), write(tmp_path, "state.json", bad)
    seen = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(seen))
    assert len(seen.ids) == 2


def test_state_holds_only_position_data(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*two_attacks())), tmp_path / "state.json"
    run([str(log), "--state", str(state)], capsys, client=fake_client(created))
    saved = json.loads(state.read_text())
    assert set(saved) == {"offset", "head_length", "head_hash"}


def test_a_connection_failure_keeps_the_failed_line_for_the_next_run(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*two_attacks())), tmp_path / "state.json"
    calls = []

    def flaky(request):
        calls.append(1)
        if len(calls) == 2:
            raise httpx.ConnectError("refused")
        return created(request)

    run([str(log), "--state", str(state)], capsys, client=fake_client(flaky))
    retry = Recorder()
    run([str(log), "--state", str(state)], capsys, client=fake_client(retry))
    assert len(retry.ids) == 1                         # only the second record is tried again


def three_attacks():
    return [record(transaction_id=f"T{n}", remote=f"198.51.100.{n}") for n in (1, 2, 3)]


def line_end(log, count):
    return len(b"".join(log.read_bytes().splitlines(keepends=True)[:count]))


def fail_second(failure):
    """A handler: the first call is stored, the second fails the given way, a third call must not happen."""
    seen = Recorder(lambda r: failure(r) if len(seen.ids) == 2 else created(r))
    return seen


@pytest.mark.parametrize("failure", [lambda r: error_reply(503, "unavailable"),
                                     lambda r: error_reply(500, "internal_error"),
                                     lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused"))])
def test_a_retryable_error_stops_the_run_and_keeps_the_failed_line_for_next_time(tmp_path, capsys, failure):
    log, state = write(tmp_path, "a.log", log_of(*three_attacks())), tmp_path / "state.json"
    seen = fail_second(failure)
    code, out, err = run([str(log), "--state", str(state)], capsys, client=fake_client(seen))
    assert code == 1 and len(seen.ids) == 2                       # line 3 was never sent
    assert json.loads(state.read_text())["offset"] == line_end(log, 1)
    assert "Stopping." in err and "Run aborted." in out


def test_rerun_after_outage_resumes_at_the_failed_line(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*three_attacks())), tmp_path / "state.json"
    first = fail_second(lambda r: error_reply(503, "unavailable"))
    run([str(log), "--state", str(state)], capsys, client=fake_client(first))
    again = Recorder()
    code, _, _ = run([str(log), "--state", str(state)], capsys, client=fake_client(again))
    assert code == 0 and len(again.ids) == 2 and again.ids[0] == first.ids[1] and first.ids[0] not in again.ids
    assert json.loads(state.read_text())["offset"] == line_end(log, 3)


def test_422_is_counted_failed_and_skipped(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*three_attacks())), tmp_path / "state.json"
    seen = fail_second(lambda r: error_reply(422, "validation_error"))
    code, out, _ = run([str(log), "--state", str(state)], capsys, client=fake_client(seen))
    assert code == 1 and len(seen.ids) == 3 and "failed 1" in out and "Run aborted." not in out
    assert json.loads(state.read_text())["offset"] == line_end(log, 3)


def test_max_events_stops_and_the_next_run_continues(tmp_path, capsys):
    log, state = tmp_path / "a.log", tmp_path / "state.json"
    log.write_text(log_of(*[record(transaction_id=f"M{i}", remote=f"198.51.100.{i}") for i in range(1, 6)]))
    first = Recorder()
    _, out, _ = run([str(log), "--state", str(state), "--max-events", "2"], capsys, client=fake_client(first))
    assert len(first.ids) == 2 and "stopped after 2" in out
    second = Recorder()
    run([str(log), "--state", str(state), "--max-events", "10"], capsys, client=fake_client(second))
    assert len(second.ids) == 3 and not set(first.ids) & set(second.ids)


# ---- dry run -------------------------------------------------------------------------------------

def test_dry_run_prints_events_sends_nothing_and_saves_no_state(tmp_path, capsys):
    log, state = write(tmp_path, "a.log", log_of(*two_attacks())), tmp_path / "state.json"

    def must_not_be_called(request):
        raise AssertionError("dry run must not call the API")

    code, out, _ = run([str(log), "--dry-run", "--state", str(state)], capsys, client=fake_client(must_not_be_called))
    events = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    assert code == 0 and len(events) == 2 and events[0]["source"] == "honeypot"
    assert not state.exists()


def test_dry_run_needs_no_api_key(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    code, out, _ = run([str(write(tmp_path, "a.log", log_of(*two_attacks()))), "--dry-run"], capsys,
                       settings_loader=lambda: IntegrationSettings(_env_file=None))
    assert code == 0 and '"source": "honeypot"' in out


def test_usage_errors():
    for argv in ([], ["a.log", "--max-events", "0"], ["a.log", "--max-events", "x"]):
        with pytest.raises(SystemExit) as caught:
            main(argv)
        assert caught.value.code == 2


# ---- through the real application ---------------------------------------------------------------

def real_client(client):
    return ThreatScopeClient(IntegrationSettings(_env_file=None, ingest_api_key=TEST_API_KEY), http_client=client)


def test_end_to_end_with_the_real_api(client, tmp_path, capsys):
    log = write(tmp_path, "a.log", log_of(record(transaction_id="E1"), record(transaction_id="E2"),
                                          record(transaction_id="E3", remote="198.51.100.9", messages=SQLI)))
    code, out, _ = run([str(log)], capsys, client=real_client(client))
    assert code == 0 and "stored 3" in out

    page = client.get("/api/v1/events", params={"source": "honeypot", "source_ip": "203.0.113.7"}).json()
    assert page["total"] == 2
    scores = sorted(e["risk_score"] for e in page["items"])
    assert scores == [55, 60]                              # high 40 + honeypot 15, then +5 for the repeat IP
    event = client.get(f"/api/v1/events/{page['items'][0]['id']}").json()
    assert [(i["type"], i["value"]) for i in event["indicators"]] == [("ip", "203.0.113.7")]
    assert CANARY not in json.dumps(event)

    run([str(log)], capsys, client=real_client(client))     # same file again: all duplicates
    assert client.get("/api/v1/events").json()["total"] == 3
