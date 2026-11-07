"""Static parsers for PDF, DOCX (zip), PNG and JPEG. Standard library only.

Nothing here executes or renders anything. Files are looked at as bytes: headers, names and
markers. Every loop is bounded, and nothing is decompressed beyond MAX_MEMBER_BYTES, so
hostile files (zip bombs, huge claimed lengths, endless padding) cost bounded time and memory.

Limits to remember: a PDF's markers can hide inside compressed streams or obfuscated names,
so "no markers found" never means "safe".
"""
import html
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

MAX_MEMBER_BYTES = 2 * 1024 * 1024     # most we read from any one part of a zip
MAX_ZIP_ENTRIES = 5000
MAX_PNG_CHUNKS = 10_000
MAX_JPEG_SEGMENTS = 2_000
MAX_JPEG_FILL_BYTES = 64

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass
class FormatResult:
    details: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)   # [{"rule": ..., "detail": ...}]
    text: str = ""                                 # text worth scanning for indicators
    urls: list = field(default_factory=list)       # URLs found in structured places
    truncated: bool = False                        # a size cap stopped us reading everything

    def note(self, rule: str, detail: str) -> None:
        self.findings.append({"rule": rule, "detail": detail})


def _malformed(result: FormatResult, detail: str) -> FormatResult:
    result.note("malformed_content", detail)
    return result


# ---- PDF ------------------------------------------------------------------------------

_PDF_MARKERS = (
    ("pdf_javascript", re.compile(rb"/(?:JavaScript|JS)(?![A-Za-z0-9])"), "contains JavaScript"),
    ("pdf_open_action", re.compile(rb"/OpenAction(?![A-Za-z0-9])"), "runs an action when opened"),
    ("pdf_additional_actions", re.compile(rb"/AA(?![A-Za-z0-9])"), "has additional-action triggers"),
    ("pdf_launch_action", re.compile(rb"/Launch(?![A-Za-z0-9])"), "can launch an external program"),
    ("pdf_embedded_file", re.compile(rb"/EmbeddedFiles?(?![A-Za-z0-9])"), "contains an embedded file"),
)
_PDF_VERSION = re.compile(rb"%PDF-(\d\.\d)")
_PDF_URI = re.compile(rb"/URI\s*\(([^()\\]{1,500})\)")
_PDF_ENCRYPT = re.compile(rb"/Encrypt(?![A-Za-z0-9])")


def parse_pdf(head: bytes) -> FormatResult:
    """Looks at the raw bytes only (no decompression, no rendering)."""
    result = FormatResult()
    version = _PDF_VERSION.search(head[:1100])
    result.details["pdf_version"] = version.group(1).decode("ascii") if version else None
    result.details["encrypted"] = bool(_PDF_ENCRYPT.search(head))
    for rule, pattern, meaning in _PDF_MARKERS:
        if pattern.search(head):
            result.note(rule, meaning)
    result.urls = [raw.decode("latin-1") for raw in _PDF_URI.findall(head)]
    return result


# ---- PNG ------------------------------------------------------------------------------

def parse_png(f, size: int) -> FormatResult:
    """Walks the chunk headers by seeking (never loads the image). Reports dimensions and any
    bytes after the IEND end marker."""
    result = FormatResult()
    pos, seen_header = len(PNG_SIGNATURE), False
    for _ in range(MAX_PNG_CHUNKS):
        f.seek(pos)
        head = f.read(8)
        if len(head) < 8:
            return _malformed(result, "PNG ends before its end marker (IEND)")
        length, kind = struct.unpack(">I4s", head)
        if not seen_header:
            if kind != b"IHDR" or length != 13:
                return _malformed(result, "PNG does not start with a valid IHDR chunk")
            body = f.read(13)
            if len(body) < 13:
                return _malformed(result, "PNG header is cut short")
            width, height, depth, colour = struct.unpack(">IIBB", body[:10])
            result.details.update(width=width, height=height, bit_depth=depth, color_type=colour)
            seen_header = True
        end = pos + 12 + length          # length + type + data + CRC
        if end > size:
            return _malformed(result, "a PNG chunk runs past the end of the file")
        if kind == b"IEND":
            trailing = size - end
            if trailing > 0:
                result.details["trailing_bytes"] = trailing
                result.note("png_trailing_data", f"{trailing} bytes follow the PNG end marker")
            return result
        pos = end
    return _malformed(result, "PNG has too many chunks to walk")


# ---- JPEG -----------------------------------------------------------------------------

_JPEG_SOF = set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
_JPEG_PROGRESSIVE = {0xC2, 0xC6, 0xCA, 0xCE}


def parse_jpeg(f, size: int) -> FormatResult:
    """Walks segment headers until the frame header (dimensions). Metadata such as EXIF/GPS is
    deliberately not read."""
    result = FormatResult()
    pos = 2
    for _ in range(MAX_JPEG_SEGMENTS):
        f.seek(pos)
        pair = f.read(2)
        if len(pair) < 2 or pair[0] != 0xFF:
            return _malformed(result, "JPEG ends early or has unexpected data between segments")
        marker, pos = pair[1], pos + 2
        fill = 0
        while marker == 0xFF:            # padding bytes
            fill += 1
            nxt = f.read(1)
            if not nxt or fill > MAX_JPEG_FILL_BYTES:
                return _malformed(result, "JPEG has endless padding or ends early")
            marker, pos = nxt[0], pos + 1
        if marker == 0xD9:               # end of image before any frame header
            break
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:   # markers without a length
            continue
        length_bytes = f.read(2)
        if len(length_bytes) < 2 or struct.unpack(">H", length_bytes)[0] < 2:
            return _malformed(result, "JPEG segment length is invalid")
        if marker in _JPEG_SOF:
            body = f.read(6)
            if len(body) < 6:
                return _malformed(result, "JPEG frame header is cut short")
            precision, height, width, components = struct.unpack(">BHHB", body)
            result.details.update(width=width, height=height, bit_depth=precision, components=components,
                                  progressive=marker in _JPEG_PROGRESSIVE)
            return result
        if marker == 0xDA:               # start of scan reached without a frame header
            break
        pos += struct.unpack(">H", length_bytes)[0]
    return _malformed(result, "JPEG has no frame header")


# ---- zip / DOCX -------------------------------------------------------------------------

_TAG = re.compile(r"<[^<>]*>")
_RELATIONSHIP = re.compile(rb"<Relationship\b[^<>]*>")
_ATTRIBUTE = re.compile(rb'([A-Za-z]+)="([^"]*)"')


def _read_part(archive: zipfile.ZipFile, name: str, result: FormatResult) -> bytes:
    """At most MAX_MEMBER_BYTES of one part. Decompression stops at the cap, so a 60 MB part
    squeezed into 60 KB (zip bomb) is never expanded."""
    try:
        with archive.open(name) as part:
            data = part.read(MAX_MEMBER_BYTES + 1)
    except (RuntimeError, zipfile.BadZipFile, zlib.error, NotImplementedError, EOFError, OSError):
        result.note("unreadable_part", f"{name} could not be read (encrypted or damaged)")
        return b""
    if len(data) > MAX_MEMBER_BYTES:
        result.truncated = True
        return data[:MAX_MEMBER_BYTES]
    return data


def inspect_zip(f) -> tuple[str, FormatResult]:
    """Returns ("docx", result) for a Word document, ("zip", result) for any other zip.
    Raises zipfile.BadZipFile when the zip structure is damaged (the caller reports that)."""
    with zipfile.ZipFile(f) as archive:
        entries = archive.infolist()
        result = FormatResult(details={"entry_count": len(entries)})
        if len(entries) > MAX_ZIP_ENTRIES:
            return "zip", _malformed(result, f"archive has more than {MAX_ZIP_ENTRIES} entries")
        names = {entry.filename for entry in entries}
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            result.note("unsupported_format", "zip archive; its contents are not examined")
            return "zip", result
        _inspect_docx(archive, names, result)
        return "docx", result


def _inspect_docx(archive: zipfile.ZipFile, names: set[str], result: FormatResult) -> None:
    has_macros = any(name.endswith("vbaProject.bin") for name in names)
    embedded = sum(1 for name in names if name.startswith("word/embeddings/"))
    result.details.update(has_macros=has_macros, embedded_objects=embedded)
    if has_macros:
        result.note("docx_macro_project", "contains a VBA macro project (stored, never run)")
    if embedded:
        result.note("docx_embedded_objects", f"{embedded} embedded object(s)")

    document = _read_part(archive, "word/document.xml", result).decode("utf-8", "replace")
    result.text = html.unescape(_TAG.sub("", document.replace("</w:p>", "\n")))

    external = 0
    if "word/_rels/document.xml.rels" in names:
        rels = _read_part(archive, "word/_rels/document.xml.rels", result)
        for tag in _RELATIONSHIP.findall(rels):
            attrs = dict(_ATTRIBUTE.findall(tag))
            if attrs.get(b"TargetMode") != b"External":
                continue
            external += 1
            target = html.unescape(attrs.get(b"Target", b"").decode("utf-8", "replace"))
            kind = attrs.get(b"Type", b"").decode("utf-8", "replace")
            result.urls.append(target)
            if kind.endswith("/attachedTemplate"):
                result.note("docx_remote_template", "loads its template from an external location")
            elif kind.endswith("/oleObject"):
                result.note("docx_linked_object", "links to an external object")
    result.details["external_links"] = external
