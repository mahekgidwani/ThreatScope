"""ModSecurity audit record -> ThreatScope honeypot event."""
import copy
import json
import re
import time as timelib
from datetime import datetime, timezone

import pytest

from app.schemas.event import EventIn
from integrations.modsec_parser import RecordSkipped, build_event, parse_time
from tests.integrations.modsec_samples import CANARY, EVALUATION, SQLI, XSS, record, rule

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def event(rec=None, **kwargs):
    return build_event(rec if rec is not None else record(**kwargs))


def skipped(rec):
    with pytest.raises(RecordSkipped) as caught:
        build_event(rec)
    return caught.value


# ---- timestamps ----------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("08/Jan/2020:09:29:17 +0000", datetime(2020, 1, 8, 9, 29, 17, tzinfo=timezone.utc)),
    ("08/Jan/2020:09:29:17 +0530", datetime(2020, 1, 8, 3, 59, 17, tzinfo=timezone.utc)),
    ("31/Dec/2025:23:59:59 -0800", datetime(2026, 1, 1, 7, 59, 59, tzinfo=timezone.utc)),
    ("2026-03-19T01:30:00Z", datetime(2026, 3, 19, 1, 30, tzinfo=timezone.utc)),
    ("2026-03-19T01:30:00+02:00", datetime(2026, 3, 18, 23, 30, tzinfo=timezone.utc)),
])
def test_parse_time(text, expected):
    assert parse_time(text) == expected


@pytest.mark.parametrize("bad", ["", "yesterday", "32/Jan/2020:09:29:17 +0000", "08/Foo/2020:09:29:17 +0000",
                                 "08/Jan/2020:25:00:00 +0000", "08/Jan/2020:09:29:17", "2026-03-19T01:30:00",
                                 "1700000000", None, 1700000000, [], "x" * 500, "08/Jan/2020:09:29:17 +9999"])
def test_bad_timestamps_are_skipped_not_guessed(bad):
    rec = record()
    rec["transaction"]["time"] = bad
    assert skipped(rec).reason == "invalid_time"


def test_missing_timestamp():
    rec = record()
    del rec["transaction"]["time"]
    assert skipped(rec).reason == "invalid_time"


# ---- source address -----------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("203.0.113.7", "203.0.113.7"), ("2001:0DB8::1", "2001:db8::1"), ("172.17.0.1", "172.17.0.1"),
])
def test_source_ip_is_canonical(raw, expected):
    assert event(remote=raw)["source_ip"] == expected


@pytest.mark.parametrize("bad", ["999.1.1.1", "", "not an ip", "fe80::1%eth0", "203.0.113.7; DROP", None, 5, "1.2.3"])
def test_bad_addresses_are_skipped(bad):
    assert skipped(record(remote=bad)).reason == "invalid_ip"


def test_missing_address():
    rec = record()
    del rec["transaction"]["remote_address"]
    assert skipped(rec).reason == "invalid_ip"


# ---- what counts as an attack event -----------------------------------------------------------

def test_no_messages_is_not_an_attack_event():
    exc = skipped(record(messages=[]))
    assert exc.reason == "no_rule_hits" and exc.benign


def test_only_evaluation_rules_is_not_an_attack_event():
    assert skipped(record(messages=EVALUATION)).reason == "no_rule_hits"


def test_missing_audit_data_is_not_an_attack_event():
    rec = record()
    del rec["audit_data"]
    assert skipped(rec).reason == "no_rule_hits"


@pytest.mark.parametrize("breaker", [
    lambda r: r.update(transaction="oops"),
    lambda r: r["audit_data"].update(messages="not a list"),
    lambda r: r["audit_data"].update(messages=[1, None, {"a": 1}]),
    lambda r: r.update(audit_data=[]),
])
def test_wrong_types_are_malformed_not_crashes(breaker):
    rec = record()
    breaker(rec)
    exc = skipped(rec)
    assert exc.reason in {"malformed", "no_rule_hits", "invalid_ip", "invalid_time"}


@pytest.mark.parametrize("junk", [5, None, "text", []])
def test_a_junk_request_section_still_gives_an_event_with_an_empty_summary(junk):
    rec = record()
    rec["request"] = junk
    assert build_event(rec)["metadata"]["request"] == {}


def test_garbage_messages_do_not_count_as_rule_hits():
    assert skipped(record(messages=["just text", "[id \"abc\"] no number", ""])).reason == "no_rule_hits"


# ---- classification ---------------------------------------------------------------------------

@pytest.mark.parametrize("messages, event_type, category", [
    (XSS, "xss_attempt", "xss"),
    (SQLI, "sqli_attempt", "sqli"),
    ([rule(932100, "Remote Command Execution: Unix Command Injection", tags=["attack-rce"],
           file="REQUEST-932-APPLICATION-ATTACK-RCE.conf")], "rce_attempt", "rce"),
    ([rule(930100, "Path Traversal Attack (/../)", tags=["attack-lfi"],
           file="REQUEST-930-APPLICATION-ATTACK-LFI.conf")], "lfi_attempt", "lfi"),
    ([rule(931100, "Possible RFI Attack", tags=["attack-rfi"],
           file="REQUEST-931-APPLICATION-ATTACK-RFI.conf")], "rfi_attempt", "rfi"),
    ([rule(933100, "PHP Injection Attack", tags=["attack-injection-php"],
           file="REQUEST-933-APPLICATION-ATTACK-PHP.conf")], "php_injection_attempt", "php_injection"),
    ([rule(913100, "Found User-Agent associated with security scanner", "CRITICAL",
           ["attack-reputation-scanner"], "REQUEST-913-SCANNER-DETECTION.conf")], "scanner_probe", "scanner"),
    ([rule(920280, "Request Missing a Host Header", "WARNING", ["attack-protocol"],
           "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")], "protocol_anomaly", "protocol"),
    ([rule(9500001, "Honeytrap hit", "CRITICAL", [], "honeytrap-before.conf")], "waf_alert", "unclassified"),
])
def test_event_type_and_category(messages, event_type, category):
    built = event(messages=messages)
    assert built["event_type"] == event_type
    assert built["metadata"]["attack_category"] == category


def test_category_falls_back_to_the_rule_number_when_tags_are_missing():
    built = event(messages=[rule(941100, "XSS Attack", tags=[])])
    assert built["event_type"] == "xss_attempt"


def test_xss_payload_that_also_trips_sql_rules_is_still_called_xss():
    sql_file = "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
    built = event(messages=[rule(i, "x", tags=["attack-xss"]) for i in (941100, 941110, 941160, 941320)]
                  + [rule(i, "y", "WARNING", ["attack-sqli"], sql_file) for i in (942110, 942431, 942432)]
                  + [rule(942130, "z", "CRITICAL", ["attack-sqli"], sql_file)] + EVALUATION)
    assert built["metadata"]["attack_category"] == "xss"
    assert set(built["metadata"]["attack_categories"]) == {"xss", "sqli"}      # the other family stays visible


def test_a_real_attack_outranks_protocol_noise():
    built = event(messages=[rule(920273, "Invalid character", "CRITICAL", ["attack-protocol"],
                                 "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")] * 3 + SQLI)
    assert built["metadata"]["attack_category"] == "sqli"


# ---- severity ---------------------------------------------------------------------------------

@pytest.mark.parametrize("modsec, api", [
    ("EMERGENCY", "critical"), ("ALERT", "critical"), ("CRITICAL", "high"), ("ERROR", "medium"),
    ("WARNING", "low"), ("NOTICE", "info"), ("INFO", "info"), ("DEBUG", "info"),
    ("2", "high"), ("0", "critical"), ("4", "low"), ("critical", "high"),
    ("SOMETHING_NEW", "info"),
])
def test_severity_mapping(modsec, api):
    assert event(messages=[rule(941100, "x", modsec, ["attack-xss"])])["severity"] == api


def test_missing_severity_is_info():
    assert event(messages=[rule(941100, "x", None, ["attack-xss"])])["severity"] == "info"


def test_highest_severity_wins():
    built = event(messages=[rule(941100, "a", "NOTICE", ["attack-xss"]), rule(941110, "b", "ERROR", ["attack-xss"]),
                            rule(941120, "c", "WARNING", ["attack-xss"])])
    assert built["severity"] == "medium"
    assert built["metadata"]["highest_severity"] == "ERROR"


# ---- metadata about rules ------------------------------------------------------------------------

def test_rule_list_has_id_message_severity_only():
    built = event()
    rules = built["metadata"]["rules"]
    assert rules[0] == {"id": 941100, "msg": "XSS Attack Detected via libinjection", "severity": "CRITICAL"}
    assert all(set(r) == {"id", "msg", "severity"} for r in rules)
    assert built["metadata"]["rule_count"] == 2          # evaluation rule 949110 is not counted


def test_rule_list_is_capped_and_unique():
    many = [rule(941000 + i, f"rule {i}", tags=["attack-xss"]) for i in range(100)] * 2
    built = event(messages=many)
    assert len(built["metadata"]["rules"]) == 20
    assert built["metadata"]["rule_count"] == 100


def test_honeytrap_rule_ids_are_flagged():
    built = event(messages=[rule(9500123, "bait touched", "CRITICAL", ["attack-generic"], "honeytrap-before.conf")]
                  + XSS)
    assert built["metadata"]["honeytrap_rule_ids"] == [9500123]


def test_cves_are_collected():
    built = event(messages=[rule(944100, "x", tags=["attack-rce", "CVE-2021-44228", "CVE-2021-44228"])])
    assert built["metadata"]["cves"] == ["CVE-2021-44228"]


def test_blocked_flag_and_response_status():
    built = event()
    assert built["metadata"]["blocked"] is True and built["metadata"]["response_status"] == 403
    rec = record()
    rec["audit_data"]["action"] = {"intercepted": False}
    assert build_event(rec)["metadata"]["blocked"] is False
    del rec["audit_data"]["action"]
    assert build_event(rec)["metadata"]["blocked"] is None


def test_crs_version_from_the_producer_list():
    assert event()["metadata"]["crs_version"] == "OWASP_CRS/3.2.0"


# ---- request details; nothing sensitive ---------------------------------------------------------

def test_request_summary():
    request = event(request_line="GET /search/page?q=hello&page=2 HTTP/1.1")["metadata"]["request"]
    assert request["method"] == "GET"
    assert request["path"] == "/search/page"
    assert request["query"] == "q=hello&page=2"
    assert request["protocol"] == "HTTP/1.1"
    assert request["host"] == "shop.example" and request["user_agent"] == "curl/7.67.0"


def test_sensitive_parameter_values_are_redacted():
    query = event(request_line="POST /login?user=bob&password=hunter2&token=abc123&api_key=zzz&x=1 HTTP/1.1"
                  )["metadata"]["request"]["query"]
    assert "hunter2" not in query and "abc123" not in query and "zzz" not in query
    assert "user=bob" in query and "password=[redacted]" in query and "x=1" in query


def test_long_values_and_many_parameters_are_cut():
    big = "&".join(f"p{i}=" + "v" * 300 for i in range(200))
    query = event(request_line=f"GET /?{big} HTTP/1.1")["metadata"]["request"]["query"]
    assert len(query) <= 500


def test_only_safe_headers_are_kept():
    headers = {"Host": "h.example", "User-Agent": "sqlmap/1.5", "Cookie": f"sid={CANARY}",
               "Authorization": f"Bearer {CANARY}", "Content-Type": "application/x-www-form-urlencoded",
               "Referer": f"http://x/?t={CANARY}", "X-Api-Key": CANARY}
    built = event(headers=headers)
    assert CANARY not in json.dumps(built, default=str)
    assert built["metadata"]["request"]["content_type"] == "application/x-www-form-urlencoded"


def test_payload_data_bodies_and_response_headers_are_never_stored():
    rec = record()
    rec["request"]["body"] = f"password={CANARY}"
    rec["audit_data"]["error_messages"] = [f"[data \"{CANARY}\"]"]
    assert CANARY not in json.dumps(build_event(rec), default=str)


@pytest.mark.parametrize("request_line", [
    "", None, 5, "GET", "GET /", "\x00\x01\x02", "GET /" + "a" * 100_000 + " HTTP/1.1",
    "G\x00ET /a\x07b HTTP/1.1", "GET /\ud800 HTTP/1.1", "GET /%00%ff?x=%zz&&&==&a HTTP/1.1",
    "CONNECT example.com:443 HTTP/1.1", "GET / HTTP/1.1 extra words here", "get /lower http/1.1",
])
def test_strange_request_lines_still_make_a_valid_event(request_line):
    built = event(request_line=request_line)
    EventIn.model_validate(json.loads(json.dumps(built, default=str)))
    request = built["metadata"]["request"]
    assert len(request.get("path", "")) <= 200


def test_non_ascii_user_agent_and_control_characters():
    built = event(headers={"User-Agent": "ünï\x00cödé\x07" + "u" * 1000, "Host": "ho\nst"})
    EventIn.model_validate(json.loads(json.dumps(built, default=str)))
    assert len(built["metadata"]["request"]["user_agent"]) <= 200


# ---- the event itself ---------------------------------------------------------------------------

def test_event_fields():
    built = event()
    assert built["source"] == "honeypot"
    assert built["source_ip"] == "203.0.113.7"
    assert built["occurred_at"] == datetime(2020, 1, 8, 9, 29, 17, tzinfo=timezone.utc)
    assert built["severity"] == "high"
    assert built["external_event_id"].startswith("modsec:")
    assert set(built) <= {"external_event_id", "source", "event_type", "occurred_at", "source_ip",
                          "severity", "description", "metadata"}
    for forbidden in ("url", "domain", "destination_ip", "file_hash"):
        assert forbidden not in built      # would link every attack to the honeypot's own address


def test_event_passes_the_real_api_schema():
    EventIn.model_validate(json.loads(json.dumps(event(), default=str)))


def test_description_states_rule_hits_not_compromise():
    built = event()
    text = (built["description"] + json.dumps(built["metadata"], default=str)).lower()
    assert "malicious" not in text and "compromised" not in text
    assert "rule" in built["description"].lower()
    assert "not a confirmed" in built["metadata"]["note"]


def test_external_id_comes_from_the_transaction_id():
    a = event(transaction_id="AAA")["external_event_id"]
    assert a == event(transaction_id="AAA", remote="198.51.100.1")["external_event_id"]
    assert a != event(transaction_id="BBB")["external_event_id"]


def test_external_id_without_a_transaction_id_uses_time_ip_and_request():
    rec1, rec2 = record(), record()
    for r in (rec1, rec2):
        del r["transaction"]["transaction_id"]
    assert build_event(rec1)["external_event_id"] == build_event(rec2)["external_event_id"]
    rec2["transaction"]["remote_address"] = "198.51.100.1"
    assert build_event(rec1)["external_event_id"] != build_event(rec2)["external_event_id"]


@pytest.mark.parametrize("tid", ["x" * 5000, "ünï\x00", "a b/c", "\ud800", 12345, ""])
def test_hostile_transaction_ids_still_give_a_valid_id(tid):
    built = event(transaction_id=tid)
    assert re.fullmatch(r"[A-Za-z0-9._:\-]+", built["external_event_id"])
    EventIn.model_validate(json.loads(json.dumps(built, default=str)))


def test_input_record_is_not_modified():
    rec = record()
    before = copy.deepcopy(rec)
    build_event(rec)
    assert rec == before


def test_hostile_messages_are_parsed_in_reasonable_time():
    nasty = ["[id \"941100\"] " + '[tag "' * 20000, "[" * 200000, '[msg "' + "\\" * 100000,
             '[id "941100"] [msg "' + "a" * 500000 + '"] [severity "CRITICAL"]']
    started = timelib.perf_counter()
    for message in nasty:
        try:
            build_event(record(messages=[message]))
        except RecordSkipped:
            pass
    assert timelib.perf_counter() - started < 5


def test_a_forged_field_inside_the_payload_does_not_override_the_real_one():
    sneaky = ('Warning. [file "/x/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [id "941100"] [msg "XSS"] '
              '[data "x \\x22] [severity \\x22INFO\\x22]"] [severity "CRITICAL"] [tag "attack-xss"]')
    assert event(messages=[sneaky])["severity"] == "high"
