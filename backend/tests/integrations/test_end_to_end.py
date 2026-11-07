"""End to end: a REAL ThreatScope server (uvicorn) on the dedicated PostgreSQL TEST database, driven over
real HTTP by the real command lines of all three adapters.

    adapter CLI -> HTTP -> FastAPI -> validation -> indicators -> risk -> PostgreSQL (threatscope_test)

Never touches the development database: the server is started with the *_test database URL and the
test guard checks the name first. The server listens on 127.0.0.1 inside the test container only.
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from app.config import get_settings
from integrations import analyse_file as file_cli
from integrations import modsec_adapter, opensquat_adapter
from integrations.config import IntegrationSettings
from tests.conftest import TEST_API_KEY
from tests.db_guard import assert_safe_test_database
from tests.integrations.modsec_samples import CANARY, SQLI, XSS, line, record
from tests.integrations.samples import make_pdf, write

pytestmark = pytest.mark.postgres        # needs real PostgreSQL; errors (never skips) when it is down

JS_PDF = make_pdf(b"1 0 obj << /OpenAction << /S /JavaScript /JS (x) >> >> endobj /URI (http://phish.example.org/a?t=SECRET)")
NOTES = ("Report from the analyst. C2 server 203.0.113.50 serves http://evil-c2.example.net/gate?token=SECRET123 "
         "and admin@bad-domain.net asked for the password.")


# ---- a real server ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def live_api(_postgres_base_engine, tmp_path_factory):
    test_url = _postgres_base_engine.url
    assert_safe_test_database(test_url, get_settings().postgres_db)       # refuses anything but *_test
    port, log_path = _free_port(), tmp_path_factory.mktemp("server") / "server.log"
    env = {**os.environ, "APP_ENV": "test", "LOG_LEVEL": "INFO", "INGEST_API_KEY": TEST_API_KEY,
           "DATABASE_URL": test_url.render_as_string(hide_password=False)}
    with open(log_path, "wb") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            env=env, cwd=str(Path(__file__).resolve().parents[2]), stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail(f"server exited early:\n{log_path.read_text(errors='replace')[-2000:]}", pytrace=False)
            try:
                if httpx.get(f"{base}/health", timeout=1).json().get("status") == "ready":
                    break
            except (httpx.HTTPError, ValueError):
                time.sleep(0.2)
        else:
            pytest.fail("server did not become ready", pytrace=False)
        yield {"base": base, "log": log_path}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture
def api(live_api, pg_engine):
    """The running server with a freshly emptied test database."""
    return live_api


# ---- helpers -----------------------------------------------------------------------------------

def settings_for(base, key=TEST_API_KEY):
    return lambda: IntegrationSettings(_env_file=None, ingest_api_key=key, threatscope_api_url=base,
                                       threatscope_timeout_seconds=5)


def fetch(base, path, **params):
    response = httpx.get(base + path, params=params, timeout=10)
    assert response.status_code == 200, response.text
    return response.json()


def all_events(base):
    return fetch(base, "/api/v1/events", limit=100)["items"]


@pytest.fixture
def material(tmp_path):
    """Harmless input for the three adapters."""
    attack_a = record(transaction_id="E2E-1", remote="203.0.113.7", messages=XSS,
                      request_line="GET /search?q=<script>alert(1)</script>&password=hunter2 HTTP/1.1",
                      headers={"Host": "shop.example", "User-Agent": "curl/8", "Cookie": f"sid={CANARY}"})
    attack_a["request"]["body"] = f"secret={CANARY}"
    attack_b = record(transaction_id="E2E-2", remote="203.0.113.7", messages=SQLI)
    attack_c = record(transaction_id="E2E-3", remote="198.51.100.9", messages=SQLI)
    clean = record(transaction_id="E2E-CLEAN", messages=[])
    return {
        "files": [write(tmp_path, "notes.txt", NOTES), write(tmp_path, "invoice.pdf", JS_PDF)],
        "domains": write(tmp_path, "feed.txt", "# newly registered\npaypa1.com\npaypal-login.net\nxn--pypal-4ve.com\nexample.com\nnot a domain\n"),
        "modsec": write(tmp_path, "modsec_audit.log",
                        "\n".join([line(attack_a), line(attack_b), "{broken json", line(clean), line(attack_c)]) + "\n"),
    }


def run_adapters(base, material, key=TEST_API_KEY):
    loader = settings_for(base, key)
    return {
        "file": file_cli.main([str(p) for p in material["files"]], settings_loader=loader),
        "domain": opensquat_adapter.main(["--keyword", "paypal", "--domains", str(material["domains"])],
                                         settings_loader=loader),
        "honeypot": modsec_adapter.main([str(material["modsec"])], settings_loader=loader),
    }


# ---- the tests -------------------------------------------------------------------------------------

def test_all_three_adapters_store_scored_events_through_the_api(api, material, capsys):
    codes = run_adapters(api["base"], material)
    out = capsys.readouterr().out
    assert codes == {"file": 0, "domain": 0, "honeypot": 0}
    assert "stored as" in out and "stored 3" in out

    events = all_events(api["base"])
    by_source = {s: [e for e in events if e["source"] == s] for s in ("file", "domain", "honeypot", "network")}
    assert {s: len(v) for s, v in by_source.items()} == {"file": 2, "domain": 3, "honeypot": 3, "network": 0}

    # every event went through the API's scoring: score = severity points + source points + repeats
    scores = {(e["source"], e["event_type"], e["severity"]): e["risk_score"] for e in events}
    assert scores[("file", "file_analysis", "info")] == 10                      # info 0 + file 10
    assert scores[("file", "file_analysis", "low")] == 20                       # PDF with JavaScript marker
    assert scores[("domain", "domain_similarity", "medium")] == 30              # medium 25 + domain 5
    assert scores[("domain", "domain_keyword_match", "low")] == 15
    assert scores[("domain", "domain_homograph", "medium")] == 30
    assert sorted(e["risk_score"] for e in by_source["honeypot"]) == [55, 55, 60]   # 40+15, +5 for the repeat IP

    # nothing the adapters sent claims more than a detection
    for event in events:
        assert event["severity"] != "critical"
        assert "malicious" not in json.dumps(event).lower()


def test_indicators_are_created_by_the_api_not_the_adapters(api, material, capsys):
    run_adapters(api["base"], material)
    base = api["base"]
    indicators = {(i["type"], i["value"]): i["sighting_count"] for i in fetch(base, "/api/v1/indicators", limit=100)["items"]}
    assert indicators[("ip", "203.0.113.7")] == 2 and indicators[("ip", "198.51.100.9")] == 1
    assert {v for t, v in indicators if t == "domain"} == {"paypa1.com", "paypal-login.net", "xn--pypal-4ve.com"}
    assert len([k for k in indicators if k[0] == "sha256"]) == 2
    # the honeypot's own address and the content found inside files are NOT indicators
    assert ("ip", "203.0.113.50") not in indicators and ("domain", "evil-c2.example.net") not in indicators
    assert all(t in {"ip", "domain", "sha256"} for t, _ in indicators)


def test_content_found_in_a_file_is_evidence_in_metadata(api, material, capsys):
    run_adapters(api["base"], material)
    notes = next(e for e in all_events(api["base"]) if e["metadata"].get("file_name") == "notes.txt")
    found = notes["metadata"]["indicators"]
    assert "203.0.113.50" in found["ips"] and "evil-c2.example.net" in found["domains"]
    assert found["urls"] == ["http://evil-c2.example.net/gate"]


def test_running_everything_again_stores_nothing_twice(api, material, capsys):
    run_adapters(api["base"], material)
    capsys.readouterr()
    before = fetch(api["base"], "/api/v1/events", limit=100)["total"]
    codes = run_adapters(api["base"], material)
    out = capsys.readouterr().out
    assert codes == {"file": 0, "domain": 0, "honeypot": 0}
    assert "already recorded" in out and "stored 0" in out
    assert fetch(api["base"], "/api/v1/events", limit=100)["total"] == before == 8
    sightings = {i["value"]: i["sighting_count"] for i in fetch(api["base"], "/api/v1/indicators", type="ip")["items"]}
    assert sightings["203.0.113.7"] == 2                                       # unchanged, not 4


def test_list_filters_work_on_adapter_events(api, material, capsys):
    run_adapters(api["base"], material)
    base = api["base"]
    assert fetch(base, "/api/v1/events", source="honeypot", source_ip="203.0.113.7")["total"] == 2
    assert fetch(base, "/api/v1/events", domain="paypa1.com")["total"] == 1
    assert fetch(base, "/api/v1/events", source="file", severity="low")["total"] == 1


def test_a_wrong_api_key_stores_nothing_and_is_reported(api, material, capsys):
    codes = run_adapters(api["base"], material, key="not-the-real-key-0123456789")
    err = capsys.readouterr().err
    assert codes == {"file": 1, "domain": 1, "honeypot": 1}
    assert "API key" in err
    assert fetch(api["base"], "/api/v1/events")["total"] == 0


def test_an_unreachable_api_is_reported_by_every_adapter(material, capsys):
    dead = f"http://127.0.0.1:{_free_port()}"
    codes = run_adapters(dead, material)
    err = capsys.readouterr().err
    assert codes == {"file": 1, "domain": 1, "honeypot": 1}
    assert err.count("could not reach") >= 3


def test_dry_runs_store_nothing(api, material, capsys):
    loader = settings_for(api["base"])
    assert file_cli.main([*map(str, material["files"]), "--dry-run"], settings_loader=loader) == 0
    assert opensquat_adapter.main(["--keyword", "paypal", "--domains", str(material["domains"]), "--dry-run"],
                                  settings_loader=loader) == 0
    assert modsec_adapter.main([str(material["modsec"]), "--dry-run"], settings_loader=loader) == 0
    assert fetch(api["base"], "/api/v1/events")["total"] == 0


def test_incremental_honeypot_reading_over_real_http(api, material, tmp_path, capsys):
    base, state = api["base"], tmp_path / "state.json"
    args = [str(material["modsec"]), "--state", str(state)]
    assert modsec_adapter.main(args, settings_loader=settings_for(base)) == 0
    first_total = fetch(base, "/api/v1/events")["total"]
    capsys.readouterr()

    assert modsec_adapter.main(args, settings_loader=settings_for(base)) == 0
    assert "read 0 record(s)" in capsys.readouterr().out                           # nothing new to read
    with open(material["modsec"], "a", encoding="utf-8") as handle:
        handle.write(line(record(transaction_id="E2E-NEW", remote="192.0.2.77", messages=XSS)) + "\n")
    assert modsec_adapter.main(args, settings_loader=settings_for(base)) == 0
    assert fetch(base, "/api/v1/events")["total"] == first_total + 1


def test_no_secret_or_payload_reaches_the_database_or_the_server_log(api, material, capsys):
    run_adapters(api["base"], material)
    stored = json.dumps(all_events(api["base"]))
    log_text = api["log"].read_text(errors="replace")
    password = get_settings().postgres_password.get_secret_value()
    for secret in (TEST_API_KEY, CANARY, "hunter2", "SECRET123", "token=SECRET"):
        assert secret not in stored, secret
    for secret in (TEST_API_KEY, CANARY, password):
        assert secret not in log_text, "secret in the server log"
    assert "POST /api/v1/events" in log_text                                         # the log itself is working
    assert "alert(1)" not in log_text                                                # no request data in the log
    assert "?" not in "".join(l for l in log_text.splitlines() if "POST /api/v1/events" in l)


def test_the_development_database_was_never_involved(api, material, capsys):
    from tests.db_support import build_postgres_engine
    assert api["base"].startswith("http://127.0.0.1:")
    engine = build_postgres_engine(get_settings())
    assert engine.url.database.endswith("_test") and engine.url.database != get_settings().postgres_db
    engine.dispose()
