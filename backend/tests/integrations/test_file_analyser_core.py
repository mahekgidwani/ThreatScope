"""File analyser: limits, hashing, type detection, text formats, indicator extraction."""
import hashlib
import json
import time

import pytest

from integrations.file_analyser import (
    MAX_DOMAINS, MAX_IPS, MAX_URLS, FileAnalysisError, analyse_file, extract_indicators,
)
from tests.integrations.samples import make_jpeg, make_pdf, make_png, write

SHA_HELLO = hashlib.sha256(b"hello").hexdigest()


def rules(report):
    return [f["rule"] for f in report.findings]


# ---- hashing and metadata ------------------------------------------------------------

def test_sha256_size_and_name(tmp_path):
    report = analyse_file(write(tmp_path, "hello.txt", b"hello"))
    assert report.sha256 == SHA_HELLO
    assert report.size == 5
    assert report.file_name == "hello.txt"
    assert report.extension == ".txt"


def test_large_file_hash_matches_hashlib_and_memory_stays_bounded(tmp_path):
    data = (b"abcdefghij" * 100_000) + b"tail"           # ~1 MB, bigger than one read chunk
    path = write(tmp_path, "big.log", data)
    report = analyse_file(path)
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    assert report.scanned_bytes <= 1024 * 1024


def test_only_the_scan_window_is_parsed_for_big_files(tmp_path):
    line = b"GET /index 203.0.113.5\n"
    path = write(tmp_path, "big.log", line * 100_000 + b"after-window 198.51.100.77\n")   # ~2.3 MB
    report = analyse_file(path)
    assert report.truncated is True
    assert report.scanned_bytes == 1024 * 1024
    assert "198.51.100.77" not in report.indicators["ips"]
    assert report.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()  # hash still covers everything


# ---- refusing files ---------------------------------------------------------------------

def test_missing_file(tmp_path):
    with pytest.raises(FileAnalysisError) as caught:
        analyse_file(tmp_path / "nope.txt")
    assert caught.value.code == "not_found"


def test_directory_is_not_a_file(tmp_path):
    with pytest.raises(FileAnalysisError) as caught:
        analyse_file(tmp_path)
    assert caught.value.code == "not_a_file"


def test_empty_file(tmp_path):
    with pytest.raises(FileAnalysisError) as caught:
        analyse_file(write(tmp_path, "empty.txt", b""))
    assert caught.value.code == "empty"


def test_oversized_file_is_refused(tmp_path):
    with pytest.raises(FileAnalysisError) as caught:
        analyse_file(write(tmp_path, "big.txt", b"x" * 101), max_bytes=100)
    assert caught.value.code == "too_large"


def test_file_exactly_at_the_limit_is_accepted(tmp_path):
    assert analyse_file(write(tmp_path, "ok.txt", b"x" * 100), max_bytes=100).size == 100


def test_unreadable_file_is_reported_not_raised_as_oserror(tmp_path, monkeypatch):
    path = write(tmp_path, "locked.txt", b"data")
    import pathlib
    real_open = pathlib.Path.open

    def deny(self, *args, **kwargs):
        if self == path:
            raise PermissionError("denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", deny)
    with pytest.raises(FileAnalysisError) as caught:
        analyse_file(path)
    assert caught.value.code == "unreadable"


def test_scripts_are_never_executed(tmp_path):
    marker = tmp_path / "executed.marker"
    script = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
    for name in ("evil.py", "evil.bat", "evil.js", "evil.ps1"):
        analyse_file(write(tmp_path, name, script))
    assert not marker.exists()


# ---- type detection ---------------------------------------------------------------------

@pytest.mark.parametrize("name, data, expected", [
    ("a.txt", b"plain words\n", "txt"),
    ("a.log", b"2026-01-01 started\n", "log"),
    ("a.json", b'{"a": 1}', "json"),
    ("a.csv", b"a,b\n1,2\n", "csv"),
    ("a.pdf", make_pdf(), "pdf"),
    ("a.png", make_png(), "png"),
    ("a.jpg", make_jpeg(), "jpeg"),
    ("a.jpeg", make_jpeg(), "jpeg"),
    ("a.unknownext", b"some text\n", "text"),
    ("noextension", b"some text\n", "text"),
])
def test_type_is_detected_from_content(tmp_path, name, data, expected):
    report = analyse_file(write(tmp_path, name, data))
    assert report.detected_type == expected
    assert report.extension_mismatch is False
    assert report.content_analysed is True


def test_unknown_binary_is_hashed_but_not_parsed(tmp_path):
    report = analyse_file(write(tmp_path, "blob.bin", bytes(range(256))))
    assert report.detected_type == "unknown"
    assert report.content_analysed is False
    assert report.sha256 == hashlib.sha256(bytes(range(256))).hexdigest()
    assert "unsupported_format" in rules(report)
    assert report.extension_mismatch is False


@pytest.mark.parametrize("magic", [b"MZ\x90\x00" + b"\x00" * 60, b"\x7fELF" + b"\x00" * 60])
def test_executables_are_identified_not_analysed(tmp_path, magic):
    report = analyse_file(write(tmp_path, "tool.dat", magic))
    assert report.detected_type == "executable"
    assert report.content_analysed is False
    assert "executable_content" in rules(report)


def test_content_beats_the_extension_and_the_mismatch_is_flagged(tmp_path):
    report = analyse_file(write(tmp_path, "invoice.pdf", make_png()))
    assert report.detected_type == "png"
    assert report.extension_mismatch is True
    assert "extension_mismatch" in rules(report)


def test_executable_disguised_as_a_document(tmp_path):
    report = analyse_file(write(tmp_path, "invoice.pdf", b"MZ\x90\x00" + b"\x00" * 60))
    assert report.detected_type == "executable"
    assert {"executable_content", "extension_mismatch"} <= set(rules(report))


def test_text_with_a_binary_extension_is_a_mismatch(tmp_path):
    report = analyse_file(write(tmp_path, "photo.png", "just some text"))
    assert report.detected_type == "text"
    assert report.extension_mismatch is True


def test_non_utf8_text_with_a_text_extension_falls_back_to_latin1(tmp_path):
    report = analyse_file(write(tmp_path, "old.log", b"caf\xe9 visited http://x.example.org/\n"))
    assert report.detected_type == "log"
    assert report.details["encoding"] == "latin-1"
    assert report.indicators["urls"] == ["http://x.example.org/"]


def test_non_utf8_without_a_text_extension_is_unknown(tmp_path):
    assert analyse_file(write(tmp_path, "blob", b"caf\xe9 stuff")).detected_type == "unknown"


def test_utf8_bom_is_accepted(tmp_path):
    report = analyse_file(write(tmp_path, "bom.txt", b"\xef\xbb\xbfhello\n"))
    assert report.detected_type == "txt" and report.details["encoding"] == "utf-8"


# ---- text formats ---------------------------------------------------------------------

def test_text_line_count(tmp_path):
    assert analyse_file(write(tmp_path, "a.txt", b"one\ntwo\nthree")).details["line_count"] == 3
    assert analyse_file(write(tmp_path, "b.txt", b"one\ntwo\n")).details["line_count"] == 2


def test_json_structure_only_no_content(tmp_path):
    report = analyse_file(write(tmp_path, "a.json", json.dumps({"password": "hunter2-secret", "k": [1, 2]})))
    assert report.detected_type == "json"
    assert report.details["json_top_level"] == "object"
    assert report.details["json_items"] == 2
    assert "hunter2-secret" not in json.dumps(report.details)


def test_invalid_json_is_text_with_a_note(tmp_path):
    report = analyse_file(write(tmp_path, "a.json", b'{"a": '))
    assert report.detected_type == "txt"
    assert "json_invalid" in rules(report)


def test_deeply_nested_json_does_not_crash(tmp_path):
    report = analyse_file(write(tmp_path, "deep.json", b"[" * 200_000 + b"]" * 200_000))
    assert "json_invalid" in rules(report)


def test_csv_rows_and_columns(tmp_path):
    report = analyse_file(write(tmp_path, "a.csv", b"a,b,c\n1,2,3\n4,5\n"))
    assert report.detected_type == "csv"
    assert report.details["csv_rows"] == 3
    assert report.details["csv_max_columns"] == 3


def test_csv_with_an_oversized_field_is_handled(tmp_path):
    report = analyse_file(write(tmp_path, "a.csv", b"a,b\n" + b"x" * 300_000 + b",1\n"))
    assert report.detected_type == "txt"
    assert "csv_unparseable" in rules(report)


# ---- indicators -----------------------------------------------------------------------

SAMPLE_TEXT = """\
Visited https://evil.example.com/path?token=SECRET123#frag and http://user:pw@198.51.100.7:8080/x
Contact admin@bad-domain.net or see report.pdf, config.json, os.path, version 1.2.3
IPs: 203.0.113.5, 999.1.1.1, 10.0.0.1, 203.0.113.5
"""


def test_extract_urls_ips_domains():
    found = extract_indicators(SAMPLE_TEXT)
    assert found["urls"] == ["https://evil.example.com/path", "http://198.51.100.7:8080/x"]
    assert set(found["ips"]) == {"198.51.100.7", "203.0.113.5", "10.0.0.1"}
    assert set(found["domains"]) == {"evil.example.com", "bad-domain.net"}


def test_credentials_and_query_strings_are_not_kept():
    blob = json.dumps(extract_indicators(SAMPLE_TEXT))
    for leaked in ("SECRET123", "pw@", "user", "token", "frag"):
        assert leaked not in blob


def test_file_names_and_code_are_not_mistaken_for_domains():
    found = extract_indicators("open report.pdf then os.path.join and self.name, main.py, notes.md, a.sh")
    assert found["domains"] == []


def test_ip_lookalikes_are_ignored():
    found = extract_indicators("999.1.1.1 256.256.256.256 1.2.3 1.2.3.4.5 01.2.3.4")
    assert found["ips"] == []


def test_duplicates_removed_order_kept():
    found = extract_indicators("203.0.113.9 and 203.0.113.1 and 203.0.113.9")
    assert found["ips"] == ["203.0.113.9", "203.0.113.1"]


def test_unicode_domain_is_stored_as_punycode_or_skipped():
    found = extract_indicators("see http://münchen.example.org/ and ｅｘａｍｐｌｅ.com")
    for domain in found["domains"]:
        assert domain.isascii()


def test_extra_urls_are_included():
    found = extract_indicators("", extra_urls=["http://203.0.113.9/t.dotm", "mailto:x@y.org", "not a url"])
    assert found["urls"] == ["http://203.0.113.9/t.dotm"]
    assert found["ips"] == ["203.0.113.9"]


def test_lists_are_capped():
    text = "\n".join(f"http://host{i}.example.org/p{i} 10.{i // 250}.{i % 250}.1 d{i}.example.net"
                     for i in range(2000))
    found = extract_indicators(text)
    assert len(found["urls"]) == MAX_URLS
    assert len(found["ips"]) == MAX_IPS
    assert len(found["domains"]) == MAX_DOMAINS


def test_very_long_urls_are_skipped():
    assert extract_indicators("http://a.example.org/" + "x" * 2000)["urls"] == []


@pytest.mark.parametrize("hostile", [
    "a" * 1_000_000,
    "a-" * 500_000,
    "a." * 500_000,
    "1." * 500_000,
    "http://" + "a" * 1_000_000,
    ("a" * 60 + ".") * 15_000,
])
def test_hostile_text_is_scanned_in_reasonable_time(hostile):
    started = time.perf_counter()
    extract_indicators(hostile)
    assert time.perf_counter() - started < 5
