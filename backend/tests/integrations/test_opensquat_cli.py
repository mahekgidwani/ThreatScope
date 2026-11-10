"""The openSquat adapter command line: files in, ThreatScope events out."""
import codecs
import json

import httpx
import pytest

from integrations.config import IntegrationSettings
from integrations.opensquat_adapter import main
from tests.integrations.fakes import KEY, created, duplicate, error_reply, fake_client
from tests.integrations.samples import write

DOMAINS = """\
# feed header comment
paypa1.com
paypal.xyz
example.com
xn--pypal-4ve.com
not a domain
paypal-secure-login.net
"""


def run(argv, capsys, **kwargs):
    code = main(argv, **kwargs)
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.fixture
def files(tmp_path):
    return {
        "keywords": write(tmp_path, "keywords.txt", "# brands\npaypal\n\nab\nPayPal\n"),
        "domains": write(tmp_path, "domains.txt", DOMAINS),
        "tmp": tmp_path,
    }


def base_args(files, *extra):
    return ["--keywords", str(files["keywords"]), "--domains", str(files["domains"]), *extra]


# ---- happy paths --------------------------------------------------------------------------

def test_findings_are_sent_and_summarised(files, capsys):
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return created(request)

    code, out, err = run(base_args(files), capsys, client=fake_client(handler))
    assert code == 0
    assert sorted(e["domain"] for e in sent) == ["paypa1.com", "paypal-secure-login.net", "paypal.xyz",
                                                 "xn--pypal-4ve.com"]
    assert all(e["source"] == "domain" for e in sent)
    assert "4 finding" in out and "stored 4" in out
    assert "skipped 1 invalid" in out                       # 'not a domain'


def test_duplicates_are_counted_not_failed(files, capsys):
    code, out, _ = run(base_args(files), capsys, client=fake_client(duplicate))
    assert code == 0 and "already recorded 4" in out


def test_repeated_keywords_are_used_once(files, capsys):
    sent = []

    def handler(request):
        sent.append(json.loads(request.content)["domain"])
        return created(request)

    run(base_args(files), capsys, client=fake_client(handler))
    assert len(sent) == len(set(sent))                      # 'paypal' and 'PayPal' are one keyword


def test_keyword_option_works_without_a_keywords_file(files, capsys):
    code, out, _ = run(["--keyword", "paypal", "--domains", str(files["domains"])], capsys,
                       client=fake_client(created))
    assert code == 0 and "stored 4" in out


def test_trusted_domains_are_skipped(files, capsys):
    trusted = write(files["tmp"], "trusted.txt", "# our own\npaypal.xyz\n")
    sent = []

    def handler(request):
        sent.append(json.loads(request.content)["domain"])
        return created(request)

    run(base_args(files, "--trusted", str(trusted)), capsys, client=fake_client(handler))
    assert "paypal.xyz" not in sent and len(sent) == 3


def test_confidence_option_changes_what_is_found(files, capsys):
    domains = write(files["tmp"], "d2.txt", "pyapal.com\n")
    args = ["--keyword", "paypal", "--domains", str(domains)]
    _, out_default, _ = run(args, capsys, client=fake_client(created))
    _, out_wide, _ = run([*args, "--confidence", "2"], capsys, client=fake_client(created))
    assert "0 finding" in out_default and "1 finding" in out_wide


def test_max_events_stops_early_and_says_so(files, capsys):
    calls = []

    def handler(request):
        calls.append(1)
        return created(request)

    code, out, _ = run(base_args(files, "--max-events", "2"), capsys, client=fake_client(handler))
    assert len(calls) == 2 and code == 0
    assert "stopped after 2" in out


# ---- dry run ------------------------------------------------------------------------------

def test_dry_run_prints_json_lines_and_sends_nothing(files, capsys):
    def must_not_be_called(request):
        raise AssertionError("dry run must not call the API")

    code, out, _ = run(base_args(files, "--dry-run"), capsys, client=fake_client(must_not_be_called))
    events = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert code == 0 and len(events) == 4
    assert {e["event_type"] for e in events} == {"domain_similarity", "domain_homograph", "domain_keyword_match"}


def test_dry_run_needs_no_api_key(files, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    code, out, _ = run(base_args(files, "--dry-run"), capsys,
                       settings_loader=lambda: IntegrationSettings(_env_file=None))
    assert code == 0 and '"source": "domain"' in out


# ---- failures -------------------------------------------------------------------------------

def test_api_rejection_is_counted_and_scanning_continues(files, capsys):
    calls = []

    def handler(request):
        calls.append(1)
        return error_reply(422, "validation_error")

    code, out, err = run(base_args(files), capsys, client=fake_client(handler))
    assert code == 1 and len(calls) == 4 and "failed 4" in out


def test_bad_key_stops_at_once(files, capsys):
    calls = []

    def handler(request):
        calls.append(1)
        return error_reply(401, "unauthorized")

    code, _, err = run(base_args(files), capsys, client=fake_client(handler))
    assert code == 1 and len(calls) == 1 and "API key" in err


def test_unreachable_api_stops_at_once(files, capsys):
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError("refused")

    code, _, err = run(base_args(files), capsys, client=fake_client(handler))
    assert code == 1 and len(calls) == 1 and "could not reach" in err


def test_missing_api_key_is_a_clear_message(files, capsys, monkeypatch):
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    code, _, err = run(base_args(files), capsys, settings_loader=lambda: IntegrationSettings(_env_file=None))
    assert code == 2 and "INGEST_API_KEY" in err and "Traceback" not in err


def test_output_never_contains_the_key(files, capsys):
    _, out, err = run(base_args(files), capsys, client=fake_client(lambda r: error_reply(500, "internal_error", KEY)))
    assert KEY not in out and KEY not in err


# ---- bad input ------------------------------------------------------------------------------

def test_missing_domains_file(files, capsys):
    code, _, err = run(["--keyword", "paypal", "--domains", str(files["tmp"] / "nope.txt")], capsys,
                       client=fake_client(created))
    assert code == 2 and "domains file" in err


def test_missing_keywords_file(files, capsys):
    code, _, err = run(["--keywords", str(files["tmp"] / "nope.txt"), "--domains", str(files["domains"])], capsys,
                       client=fake_client(created))
    assert code == 2 and "keywords file" in err


def test_no_valid_keywords(files, capsys):
    empty = write(files["tmp"], "k.txt", "# nothing\nab\n")
    code, _, err = run(["--keywords", str(empty), "--domains", str(files["domains"])], capsys,
                       client=fake_client(created))
    assert code == 2 and "no valid keywords" in err


def test_no_keywords_given_is_a_usage_error(files):
    with pytest.raises(SystemExit) as caught:
        main(["--domains", str(files["domains"])])
    assert caught.value.code == 2


@pytest.mark.parametrize("bad", ["5", "-1", "x"])
def test_confidence_must_be_0_to_4(files, bad):
    with pytest.raises(SystemExit) as caught:
        main(base_args(files, "--confidence", bad))
    assert caught.value.code == 2


def test_hostile_domain_file_does_not_crash(files, capsys):
    hostile = write(files["tmp"], "bad.txt",
                    b"paypa1.com\n" + b"a" * 5_000_000 + b"\n" + b"\xff\xfe\x00binary\x00\n" + b"paypal.xyz\n")
    code, out, _ = run(["--keyword", "paypal", "--domains", str(hostile)], capsys, client=fake_client(created))
    assert code == 0 and "stored 2" in out and "skipped 2 invalid" in out


def test_domain_list_encodings_all_work(files, capsys):
    text = "paypa1.com paypal.xyz example.com ".replace(" ", chr(10))
    encodings = {"utf8": text.encode("utf-8"), "bom": text.encode("utf-8-sig"),
                 "utf16": text.encode("utf-16"), "utf16be": codecs.BOM_UTF16_BE + text.encode("utf-16-be")}
    results = {}
    for name, raw in encodings.items():
        domains = write(files["tmp"], f"{name}.txt", raw)
        code, out, _ = run(["--keyword", "paypal", "--domains", str(domains), "--dry-run"], capsys)
        assert code == 0
        results[name] = sorted(json.loads(line)["domain"] for line in out.splitlines() if line.startswith("{"))
        assert "Checked 3 domain(s)" in out and "skipped 0 invalid" in out
    assert results["utf8"] == ["paypa1.com", "paypal.xyz"]            # first domain not dropped
    assert all(found == results["utf8"] for found in results.values())
    # keyword and trusted files get the same treatment
    keywords = write(files["tmp"], "kw16.txt", ("paypal" + chr(10)).encode("utf-16"))
    trusted = write(files["tmp"], "tr16.txt", ("paypal.xyz" + chr(10)).encode("utf-16"))
    domains = write(files["tmp"], "d.txt", text)
    code, out, _ = run(["--keywords", str(keywords), "--trusted", str(trusted), "--domains", str(domains), "--dry-run"], capsys)
    assert code == 0 and "against 1 keyword(s): 1 finding(s)" in out
