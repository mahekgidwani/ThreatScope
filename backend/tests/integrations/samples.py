"""Harmless sample files for the file-analyser tests. Everything is built from plain bytes;
nothing here is, or does, anything dangerous."""
import io
import struct
import zlib
import zipfile
from pathlib import Path


def write(directory: Path, name: str, data: bytes | str) -> Path:
    path = directory / name
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def make_png(width: int = 1, height: int = 1, trailing: bytes = b"") -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header)
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + _png_chunk(b"IEND", b"") + trailing)


def make_jpeg(width: int = 2, height: int = 3) -> bytes:
    jfif = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = (b"\xff\xc0" + struct.pack(">H", 17) + struct.pack(">BHHB", 8, height, width, 3)
            + b"\x01\x22\x00\x02\x11\x01\x03\x11\x01")
    sos = b"\xff\xda" + struct.pack(">H", 12) + b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    return b"\xff\xd8" + jfif + sof0 + sos + b"\x00" + b"\xff\xd9"


def make_pdf(body: bytes = b"", version: bytes = b"1.7") -> bytes:
    return b"%PDF-" + version + b"\n" + body + b"\n%%EOF\n"


def make_docx(text: str = "Hello", extra: dict[str, bytes] | None = None, rels: bytes | None = None) -> bytes:
    document = ('<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>' + text
                + "</w:t></w:r></w:p></w:body></w:document>").encode("utf-8")
    parts = {"[Content_Types].xml": b"<Types/>", "word/document.xml": document}
    if rels is not None:
        parts["word/_rels/document.xml.rels"] = rels
    parts.update(extra or {})
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def make_rels(target: str, rel_type: str, external: bool = True) -> bytes:
    mode = ' TargetMode="External"' if external else ""
    return (f'<?xml version="1.0"?><Relationships><Relationship Id="rId1" Type="{rel_type}" '
            f'Target="{target}"{mode}/></Relationships>').encode("utf-8")


REL_BASE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
