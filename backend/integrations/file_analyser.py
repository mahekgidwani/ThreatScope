"""Lightweight STATIC file analysis -> one ThreatScope `file` event.

What it does: SHA-256 (streamed), type detection from content, basic structure metadata, and IPs /
domains / URLs found in the file. What it never does: execute, open with an application, run
macros or scripts, render, or store file contents. Findings are "worth a human look" markers, not a
malware verdict; the event says so.

Bounded work: files over `max_bytes` are refused, only the first SCAN_BYTES are held in memory,
zip parts are capped (see file_formats), and every list that goes into the event is capped so the
event always fits the API's metadata limit.

Why the indicators live in `metadata`: the API turns only top-level event fields (file_hash, url,
domain, IPs) into indicator rows. A file event therefore produces one `sha256` indicator; the IPs,
domains and URLs found INSIDE the file are recorded as evidence in the metadata. Making them
separate indicators would need extra events that inflate the file hash's sighting count.
"""
import codecs
import csv
import hashlib
import io
import ipaddress
import json
import re
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from app.schemas.event import normalise_domain
from integrations.client import stable_event_id
from integrations.textutil import clean
from integrations.file_formats import (
    PNG_SIGNATURE, FormatResult, inspect_zip, parse_jpeg, parse_pdf, parse_png,
)

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
SCAN_BYTES = 1024 * 1024
HASH_CHUNK = 1024 * 1024
MAX_URLS, MAX_IPS, MAX_DOMAINS = 30, 50, 50
MAX_URL_LENGTH = 500
MAX_NAME_LENGTH = 100
ANALYSER_ID = "threatscope-static-1"
NOTE = ("This is static analysis only. Findings are items worth a human look, "
        "not a malware verdict.")

TEXT_TYPES = {".txt": "txt", ".log": "log", ".json": "json", ".csv": "csv"}
BINARY_TYPES = {".pdf": "pdf", ".docx": "docx", ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg"}
RECOGNISED_BINARY = {"pdf", "docx", "png", "jpeg", "zip", "executable"}
CONTENT_ANALYSED = {"pdf", "docx", "png", "jpeg", "json", "csv", "log", "txt", "text"}

# Findings that make an event "low" severity instead of "info". Everything else is a note.
REVIEW_RULES = frozenset({
    "pdf_javascript", "pdf_open_action", "pdf_additional_actions", "pdf_launch_action",
    "pdf_embedded_file", "docx_macro_project", "docx_embedded_objects", "docx_remote_template",
    "docx_linked_object", "png_trailing_data", "executable_content", "extension_mismatch",
})

# Bare domains (not inside a URL) are only reported for these TLDs. A full list would need a data
# file, and without one things like report.pdf, os.path or main.py look like domains. Hosts of
# URLs are always reported, whatever their TLD. TLDs that are also common file extensions
# (.py .sh .pl .md .rs .ml .zip ...) are left out on purpose.
COMMON_TLDS = frozenset(
    "com net org edu gov mil int info biz io co ai app dev xyz top site online store shop club live cloud "
    "tech me tv cc us uk de fr nl ru cn jp in br au ca it es se no fi ch at be cz ro ua tr kr za mx ar ir "
    "pw tk ga cf gq su ws to ly gl click link work support icu vip pro mobi asia".split())

_URL = re.compile(r"(?:https?|ftp)://[^\s<>\"'`\\^{}|]+", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_DOMAIN = re.compile(r"(?<![\w.\-])[A-Za-z0-9](?:[A-Za-z0-9\-]*\.)+[A-Za-z]{2,24}(?![\w\-]|\.\w)")


class FileAnalysisError(Exception):
    """The file cannot be analysed. `code`: not_found, not_a_file, empty, too_large, unreadable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class FileReport:
    file_name: str
    size: int
    sha256: str
    extension: str
    detected_type: str
    extension_mismatch: bool
    content_analysed: bool
    scanned_bytes: int
    truncated: bool
    details: dict = field(default_factory=dict)
    indicators: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    @property
    def review_markers(self) -> list[str]:
        return list(dict.fromkeys(f["rule"] for f in self.findings if f["rule"] in REVIEW_RULES))


def printable(text: str, limit: int = MAX_NAME_LENGTH) -> str:
    """`clean` text, or "unnamed" when nothing is left (for file names)."""
    return clean(text, limit) or "unnamed"


# ---- indicators ---------------------------------------------------------------------------

def _clean_url(raw: str) -> str | None:
    """scheme://host[:port]/path - without credentials, query string or fragment, which may hold secrets."""
    url = raw.rstrip(".,;:!?'\")]}>")
    if len(url) > MAX_URL_LENGTH or not url.isascii():
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    return f"{parts.scheme.lower()}://{netloc}{parts.path}"


def extract_indicators(text: str, extra_urls=()) -> dict:
    """{"ips": [...], "domains": [...], "urls": [...]}: unique, in order of appearance, capped."""
    urls = [u for u in (_clean_url(raw) for raw in [*_URL.findall(text), *extra_urls]) if u]
    ips, domains = [], []
    for token in _IPV4.findall(text):
        try:
            ips.append(str(ipaddress.IPv4Address(token)))
        except ValueError:
            pass
    for candidate in _DOMAIN.findall(text):
        if candidate.rsplit(".", 1)[1].lower() in COMMON_TLDS:
            _add_domain(domains, candidate)
    for url in dict.fromkeys(urls):
        host = urlsplit(url).hostname
        try:
            ips.append(str(ipaddress.ip_address(host)))
        except ValueError:
            _add_domain(domains, host)
    return {"ips": list(dict.fromkeys(ips))[:MAX_IPS],
            "domains": list(dict.fromkeys(domains))[:MAX_DOMAINS],
            "urls": list(dict.fromkeys(urls))[:MAX_URLS]}


def _add_domain(domains: list, name: str) -> None:
    try:
        domains.append(normalise_domain(name))   # the API's own rules, so values always agree
    except ValueError:
        pass


# ---- reading the file ---------------------------------------------------------------------

def _hash_and_head(f, max_bytes: int) -> tuple[str, int, bytes]:
    digest, size, head = hashlib.sha256(), 0, b""
    while chunk := f.read(HASH_CHUNK):
        size += len(chunk)
        if size > max_bytes:   # the file grew after the size check
            raise FileAnalysisError("too_large", f"file is too large (limit {max_bytes} bytes)")
        if len(head) < SCAN_BYTES:
            head += chunk[:SCAN_BYTES - len(head)]
        digest.update(chunk)
    return digest.hexdigest(), size, head


def _decode_text(head: bytes, truncated: bool, extension: str) -> tuple[str, str] | None:
    if b"\x00" in head:
        return None
    try:
        decoder = codecs.getincrementaldecoder("utf-8-sig")(errors="strict")
        return decoder.decode(head, final=not truncated), "utf-8"
    except UnicodeDecodeError:
        return (head.decode("latin-1"), "latin-1") if extension in TEXT_TYPES else None


def _analyse_text(text: str, extension: str, truncated: bool, result: FormatResult) -> str:
    """Fills `result` and returns the detected type (json/csv only when the content really parses)."""
    result.text = text
    result.details["line_count"] = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
    declared = TEXT_TYPES.get(extension)
    if declared == "json" and not truncated:
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            result.note("json_invalid", "file ends in .json but is not valid JSON")
            return "txt"
        kind = {dict: "object", list: "array"}.get(type(value), "value")
        result.details["json_top_level"] = kind
        result.details["json_items"] = len(value) if kind != "value" else None
    elif declared == "csv":
        try:
            rows = columns = 0
            for row in csv.reader(io.StringIO(text)):
                rows, columns = rows + 1, max(columns, len(row))
        except csv.Error:
            result.note("csv_unparseable", "file ends in .csv but could not be read as CSV")
            return "txt"
        result.details.update(csv_rows=rows, csv_max_columns=columns)
    return declared or "text"


def analyse_file(path, max_bytes: int = DEFAULT_MAX_BYTES) -> FileReport:
    """Static analysis of one file. Raises FileAnalysisError when it cannot be analysed."""
    path = Path(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        raise FileAnalysisError("not_found", "file not found") from None
    except OSError:
        raise FileAnalysisError("unreadable", "file cannot be read") from None
    if not stat.S_ISREG(info.st_mode):
        raise FileAnalysisError("not_a_file", "path is not a file")
    if info.st_size == 0:
        raise FileAnalysisError("empty", "file is empty")
    if info.st_size > max_bytes:
        raise FileAnalysisError("too_large", f"file is too large (limit {max_bytes} bytes)")
    try:
        with path.open("rb") as f:
            sha256, size, head = _hash_and_head(f, max_bytes)
            if size == 0:
                raise FileAnalysisError("empty", "file is empty")
            return _build_report(f, path, sha256, size, head)
    except OSError:
        raise FileAnalysisError("unreadable", "file cannot be read") from None


def _build_report(f, path: Path, sha256: str, size: int, head: bytes) -> FileReport:
    extension = printable(path.suffix.lower(), 20) if path.suffix else ""
    window_truncated = size > len(head)
    result, detected, truncated = FormatResult(), "unknown", False

    f.seek(0)
    if head.lstrip(b"\xef\xbb\xbf\r\n\t ").startswith(b"%PDF-"):
        detected, result, truncated = "pdf", parse_pdf(head), window_truncated
    elif head.startswith(PNG_SIGNATURE):
        detected, result = "png", parse_png(f, size)
    elif head.startswith(b"\xff\xd8\xff"):
        detected, result = "jpeg", parse_jpeg(f, size)
    elif head.startswith(b"PK\x03\x04"):
        try:
            detected, result = inspect_zip(f)
        except zipfile.BadZipFile:
            detected = "zip"
            result.note("malformed_content", "zip structure is damaged")
        truncated = result.truncated
    elif (head.startswith(b"MZ") and b"\x00" in head[:64]) or head.startswith(b"\x7fELF"):
        detected = "executable"
        result.note("executable_content", "executable file header; the file is not examined further")
    else:
        decoded = _decode_text(head, window_truncated, extension)
        if decoded is None:
            result.note("unsupported_format", "binary format that is not analysed")
        else:
            text, encoding = decoded
            result.details["encoding"] = encoding
            detected, truncated = _analyse_text(text, extension, window_truncated, result), window_truncated

    mismatch = _extension_mismatch(extension, detected)
    if mismatch:
        result.note("extension_mismatch", f"extension {extension} but the content looks like {detected}")
    if truncated:
        result.note("truncated_scan", f"only the first {SCAN_BYTES} bytes were examined")

    analysed = detected in CONTENT_ANALYSED
    return FileReport(
        file_name=printable(path.name), size=size, sha256=sha256, extension=extension,
        detected_type=detected, extension_mismatch=mismatch, content_analysed=analysed,
        scanned_bytes=len(head), truncated=truncated, details=result.details,
        indicators=extract_indicators(result.text, result.urls) if analysed
        else {"ips": [], "domains": [], "urls": []},
        findings=result.findings)


def _extension_mismatch(extension: str, detected: str) -> bool:
    expected = BINARY_TYPES.get(extension)
    if expected:
        return detected not in {expected, "zip"} if expected == "docx" else detected != expected
    return extension in TEXT_TYPES and detected in RECOGNISED_BINARY


# ---- the event ----------------------------------------------------------------------------

def build_event(report: FileReport, now: datetime | None = None) -> dict:
    """The dict to send with ThreatScopeClient.submit_event (shape defined by the API's EventIn).

    `external_event_id` comes from the SHA-256, so analysing the same content again (under any
    name) is a duplicate and is not stored twice."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    name = printable(report.file_name)
    markers = report.review_markers
    description = f"Static analysis of {name} ({report.detected_type}, {report.size} bytes)"
    if markers:
        description += f": {len(markers)} marker(s) worth review ({', '.join(markers)})"
    return {
        "external_event_id": stable_event_id("file", report.sha256),
        "source": "file",
        "event_type": "file_analysis",
        "occurred_at": now,
        "file_hash": report.sha256,
        "severity": "low" if markers else "info",
        "description": description,
        "metadata": {
            "analyser": ANALYSER_ID, "file_name": name, "file_size": report.size,
            "extension": report.extension, "detected_type": report.detected_type,
            "extension_mismatch": report.extension_mismatch, "content_analysed": report.content_analysed,
            "scanned_bytes": report.scanned_bytes, "truncated": report.truncated,
            "details": report.details, "indicators": report.indicators, "findings": report.findings,
            "review_markers": markers, "note": NOTE,
        },
    }
