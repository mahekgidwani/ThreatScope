"""From report to ThreatScope event, including a round trip through the REAL API."""
import json
from datetime import datetime, timezone

import pytest

from app.schemas.event import EventIn
from integrations.client import ThreatScopeClient
from integrations.config import IntegrationSettings
from integrations.file_analyser import analyse_file, build_event
from tests.conftest import TEST_API_KEY
from tests.integrations.samples import make_docx, make_pdf, write

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
JS_PDF = make_pdf(b"<< /OpenAction << /S /JavaScript /JS (x) >> >> /URI (http://phish.example.org/a)")


def event_for(tmp_path, name="a.txt", data=b"hello world\n", **kwargs):
    return build_event(analyse_file(write(tmp_path, name, data)), now=NOW, **kwargs)


def test_event_fields(tmp_path):
    report = analyse_file(write(tmp_path, "a.txt", b"hello"))
    event = build_event(report, now=NOW)
    assert event["source"] == "file"
    assert event["event_type"] == "file_analysis"
    assert event["file_hash"] == report.sha256
    assert event["occurred_at"] == NOW
    assert event["severity"] == "info"
    assert event["external_event_id"].startswith("file:")
    assert set(event) <= {"external_event_id", "source", "event_type", "occurred_at", "file_hash",
                          "severity", "description", "metadata"}


def test_event_passes_the_real_api_schema(tmp_path):
    EventIn.model_validate(json.loads(json.dumps(event_for(tmp_path, "a.pdf", JS_PDF), default=str)))


def test_same_content_gives_the_same_external_id_even_under_another_name(tmp_path):
    first = event_for(tmp_path, "one.txt", b"same")
    second = event_for(tmp_path, "two.log", b"same")
    assert first["external_event_id"] == second["external_event_id"]
    assert first["external_event_id"] != event_for(tmp_path, "three.txt", b"different")["external_event_id"]


def test_review_markers_make_severity_low_and_are_listed(tmp_path):
    event = event_for(tmp_path, "a.pdf", JS_PDF)
    assert event["severity"] == "low"
    assert {"pdf_javascript", "pdf_open_action"} <= set(event["metadata"]["review_markers"])
    assert "review" in event["description"]


def test_notes_alone_keep_severity_info(tmp_path):
    event = event_for(tmp_path, "a.bin", bytes(range(256)))       # unsupported format = a note, not a marker
    assert event["severity"] == "info"
    assert event["metadata"]["review_markers"] == []


def test_nothing_claims_malware(tmp_path):
    event = event_for(tmp_path, "a.pdf", JS_PDF)
    text = (event["description"] + json.dumps(event["metadata"], default=str)).lower()
    assert "malicious" not in text.replace("not a malware verdict", "")
    assert "static analysis only" in event["metadata"]["note"]
    assert "not a malware verdict" in event["metadata"]["note"]


def test_metadata_has_structure_and_indicators_but_no_content(tmp_path):
    event = event_for(tmp_path, "a.log", b"password=hunter2 from 203.0.113.5 via http://x.example.org/?k=abc\n")
    meta = event["metadata"]
    assert meta["file_name"] == "a.log" and meta["detected_type"] == "log"
    assert meta["indicators"]["ips"] == ["203.0.113.5"]
    assert "hunter2" not in json.dumps(meta)
    assert "k=abc" not in json.dumps(meta)


def test_odd_file_names_cannot_break_the_event(tmp_path):
    report = analyse_file(write(tmp_path, "a.txt", b"hello"))
    for name in ["x" * 500, "bell\x07name.txt", "lone\ud800surrogate.txt", "   .txt", "ünïcode名.txt"]:
        report.file_name = name
        EventIn.model_validate(json.loads(json.dumps(build_event(report, now=NOW), default=str)))


def test_naive_now_is_refused(tmp_path):
    report = analyse_file(write(tmp_path, "a.txt", b"hello"))
    with pytest.raises(ValueError):
        build_event(report, now=datetime(2026, 1, 1))


# ---- through the real application ----------------------------------------------------------

def real_client(client):
    return ThreatScopeClient(IntegrationSettings(_env_file=None, ingest_api_key=TEST_API_KEY), http_client=client)


def test_stored_scored_and_one_indicator(client, tmp_path):
    result = real_client(client).submit_event(event_for(tmp_path, "a.txt", b"hello"))
    assert result.created
    stored = client.get(f"/api/v1/events/{result.event_id}").json()
    assert stored["source"] == "file" and stored["risk_score"] == 10        # info 0 + file 10
    assert [(i["type"]) for i in stored["indicators"]] == ["sha256"]
    assert stored["metadata"]["detected_type"] == "txt"


def test_review_markers_raise_the_score_by_the_low_severity_points(client, tmp_path):
    result = real_client(client).submit_event(event_for(tmp_path, "a.pdf", JS_PDF))
    assert client.get(f"/api/v1/events/{result.event_id}").json()["risk_score"] == 20   # low 10 + file 10


def test_analysing_the_same_file_twice_is_a_duplicate(client, tmp_path):
    api = real_client(client)
    first = api.submit_event(event_for(tmp_path, "a.txt", b"hello"))
    second = api.submit_event(event_for(tmp_path, "renamed.txt", b"hello"))
    assert second.duplicate and second.event_id == first.event_id
    assert client.get("/api/v1/events").json()["total"] == 1
    assert client.get("/api/v1/indicators").json()["items"][0]["sighting_count"] == 1


def test_worst_case_indicator_lists_still_fit_the_api_limits(client, tmp_path):
    lines = [f"http://h{i}.example.org/{'p' * 400}{i} 10.{i // 250}.{i % 250}.1 d{i}.example.net"
             for i in range(3000)]
    event = event_for(tmp_path, "huge.log", "\n".join(lines))
    assert real_client(client).submit_event(event).created


def test_docx_event_round_trip(client, tmp_path):
    event = event_for(tmp_path, "a.docx", make_docx("see https://docs.example.net/a"))
    assert real_client(client).submit_event(event).created
