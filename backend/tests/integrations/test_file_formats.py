"""PDF, DOCX, PNG and JPEG static parsing, including malformed and hostile files."""
import io
import time
import tracemalloc
import zipfile

from integrations.file_analyser import analyse_file
from tests.integrations.samples import (
    REL_BASE, make_docx, make_jpeg, make_pdf, make_png, make_rels, write,
)


def rules(report):
    return [f["rule"] for f in report.findings]


# ---- PDF ------------------------------------------------------------------------------

def test_plain_pdf_has_no_findings(tmp_path):
    report = analyse_file(write(tmp_path, "a.pdf", make_pdf(b"1 0 obj << /Type /Catalog >> endobj")))
    assert report.detected_type == "pdf"
    assert report.details["pdf_version"] == "1.7"
    assert report.details["encrypted"] is False
    assert report.findings == []


def test_pdf_markers_and_uris(tmp_path):
    body = (b"1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n"
            b"2 0 obj << /S /URI /URI (http://phish.example.org/login?u=1) >> endobj\n"
            b"3 0 obj << /S /Launch >> endobj 4 0 obj << /Type /EmbeddedFile >> endobj")
    report = analyse_file(write(tmp_path, "a.pdf", make_pdf(body)))
    assert {"pdf_javascript", "pdf_open_action", "pdf_launch_action", "pdf_embedded_file"} <= set(rules(report))
    assert report.indicators["urls"] == ["http://phish.example.org/login"]
    assert report.indicators["domains"] == ["phish.example.org"]


def test_json_word_in_a_pdf_is_not_a_javascript_marker(tmp_path):
    report = analyse_file(write(tmp_path, "a.pdf", make_pdf(b"<< /JSON 1 /JSX 2 >>")))
    assert "pdf_javascript" not in rules(report)


def test_pdf_encrypted_flag(tmp_path):
    report = analyse_file(write(tmp_path, "a.pdf", make_pdf(b"trailer << /Encrypt 5 0 R >>")))
    assert report.details["encrypted"] is True


def test_pdf_header_may_follow_a_few_junk_bytes(tmp_path):
    assert analyse_file(write(tmp_path, "a.pdf", b"\xef\xbb\xbf" + make_pdf())).detected_type == "pdf"


def test_truncated_pdf_does_not_crash(tmp_path):
    report = analyse_file(write(tmp_path, "a.pdf", b"%PDF-1.4"))
    assert report.detected_type == "pdf"
    assert report.extension_mismatch is False


def test_binary_garbage_in_a_pdf_does_not_crash(tmp_path):
    report = analyse_file(write(tmp_path, "a.pdf", make_pdf(bytes(range(256)) * 400)))
    assert report.detected_type == "pdf"


# ---- DOCX -----------------------------------------------------------------------------

def test_plain_docx(tmp_path):
    report = analyse_file(write(tmp_path, "a.docx", make_docx("Please visit https://docs.example.net/a now")))
    assert report.detected_type == "docx"
    assert report.findings == []
    assert report.details["has_macros"] is False
    assert report.indicators["urls"] == ["https://docs.example.net/a"]
    assert report.indicators["domains"] == ["docs.example.net"]


def test_docx_text_content_is_never_stored(tmp_path):
    report = analyse_file(write(tmp_path, "a.docx", make_docx("my secret diary entry")))
    assert "secret diary" not in str(report.details) + str(report.indicators) + str(report.findings)


def test_docx_with_macro_project(tmp_path):
    report = analyse_file(write(tmp_path, "a.docx", make_docx(extra={"word/vbaProject.bin": b"\x00\x01"})))
    assert "docx_macro_project" in rules(report)
    assert report.details["has_macros"] is True


def test_docx_with_embedded_objects(tmp_path):
    report = analyse_file(write(tmp_path, "a.docx", make_docx(extra={"word/embeddings/oleObject1.bin": b"x"})))
    assert "docx_embedded_objects" in rules(report)
    assert report.details["embedded_objects"] == 1


def test_docx_remote_template(tmp_path):
    rels = make_rels("http://203.0.113.9/t.dotm", REL_BASE + "/attachedTemplate")
    report = analyse_file(write(tmp_path, "a.docx", make_docx(rels=rels)))
    assert "docx_remote_template" in rules(report)
    assert report.indicators["urls"] == ["http://203.0.113.9/t.dotm"]
    assert report.indicators["ips"] == ["203.0.113.9"]


def test_ordinary_external_hyperlink_is_an_indicator_not_a_marker(tmp_path):
    rels = make_rels("https://example.org/page?a=1&amp;b=2", REL_BASE + "/hyperlink")
    report = analyse_file(write(tmp_path, "a.docx", make_docx(rels=rels)))
    assert report.findings == []
    assert report.indicators["urls"] == ["https://example.org/page"]


def test_internal_relationship_is_ignored(tmp_path):
    rels = make_rels("styles.xml", REL_BASE + "/styles", external=False)
    assert analyse_file(write(tmp_path, "a.docx", make_docx(rels=rels))).indicators["urls"] == []


def test_zip_without_word_parts_is_a_plain_zip(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", "hi")
    report = analyse_file(write(tmp_path, "bundle.zip", buffer.getvalue()))
    assert report.detected_type == "zip"
    assert report.content_analysed is False
    assert report.extension_mismatch is False


def test_plain_zip_named_docx_is_not_flagged_as_a_mismatch(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", "hi")
    report = analyse_file(write(tmp_path, "a.docx", buffer.getvalue()))
    assert report.detected_type == "zip"
    assert report.extension_mismatch is False


def test_malformed_zip_does_not_crash(tmp_path):
    report = analyse_file(write(tmp_path, "a.docx", b"PK\x03\x04" + b"junk" * 50))
    assert report.detected_type == "zip"
    assert "malformed_content" in rules(report)


def test_truncated_docx_does_not_crash(tmp_path):
    data = make_docx("hello")
    report = analyse_file(write(tmp_path, "a.docx", data[: len(data) // 2]))
    assert "malformed_content" in rules(report)


def test_zip_bomb_member_is_read_only_up_to_a_cap(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"A" * (60 * 1024 * 1024))    # 60 MB of 'A', ~60 KB zipped
    path = write(tmp_path, "bomb.docx", buffer.getvalue())
    assert path.stat().st_size < 1024 * 1024
    tracemalloc.start()
    started = time.perf_counter()
    report = analyse_file(path)
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert elapsed < 5
    assert peak < 16 * 1024 * 1024          # the 60 MB part was never expanded in memory
    assert report.detected_type == "docx"
    assert report.truncated is True


def test_zip_with_a_huge_number_of_entries_is_refused_safely(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<w:t>x</w:t>")
        for i in range(6000):
            archive.writestr(f"f{i}", b"")
    report = analyse_file(write(tmp_path, "many.docx", buffer.getvalue()))
    assert "malformed_content" in rules(report)


def test_encrypted_member_is_noted_not_fatal(tmp_path):
    data = bytearray(make_docx("hello"))
    for signature, flag_offset in ((b"PK", 6), (b"PK", 8)):   # local + central headers
        start = 0
        while (start := data.find(signature, start)) != -1:
            data[start + flag_offset] |= 0x01                                    # "this entry is encrypted"
            start += 4
    report = analyse_file(write(tmp_path, "enc.docx", bytes(data)))
    assert report.detected_type == "docx"
    assert "unreadable_part" in rules(report)


# ---- PNG ------------------------------------------------------------------------------

def test_png_dimensions(tmp_path):
    report = analyse_file(write(tmp_path, "a.png", make_png(640, 480)))
    assert (report.details["width"], report.details["height"]) == (640, 480)
    assert report.findings == []


def test_png_with_data_after_the_end_marker(tmp_path):
    report = analyse_file(write(tmp_path, "a.png", make_png(trailing=b"MZ" + b"A" * 100)))
    assert "png_trailing_data" in rules(report)
    assert report.details["trailing_bytes"] == 102


def test_truncated_png(tmp_path):
    report = analyse_file(write(tmp_path, "a.png", make_png()[:30]))
    assert report.detected_type == "png"
    assert "malformed_content" in rules(report)


def test_png_signature_only(tmp_path):
    report = analyse_file(write(tmp_path, "a.png", b"\x89PNG\r\n\x1a\n"))
    assert "malformed_content" in rules(report)


def test_png_with_absurd_chunk_length_does_not_hang(tmp_path):
    data = make_png()[:8] + b"\xff\xff\xff\xffIHDR" + b"\x00" * 20
    started = time.perf_counter()
    report = analyse_file(write(tmp_path, "a.png", data))
    assert time.perf_counter() - started < 2
    assert "malformed_content" in rules(report)


# ---- JPEG -----------------------------------------------------------------------------

def test_jpeg_dimensions(tmp_path):
    report = analyse_file(write(tmp_path, "a.jpg", make_jpeg(width=800, height=600)))
    assert (report.details["width"], report.details["height"]) == (800, 600)
    assert report.details["components"] == 3
    assert report.findings == []


def test_truncated_jpeg(tmp_path):
    report = analyse_file(write(tmp_path, "a.jpg", b"\xff\xd8\xff"))
    assert report.detected_type == "jpeg"
    assert "malformed_content" in rules(report)


def test_jpeg_without_a_frame_header(tmp_path):
    report = analyse_file(write(tmp_path, "a.jpg", b"\xff\xd8\xff\xe0\x00\x04ab\xff\xd9"))
    assert "malformed_content" in rules(report)


def test_jpeg_with_endless_padding_does_not_hang(tmp_path):
    started = time.perf_counter()
    report = analyse_file(write(tmp_path, "a.jpg", b"\xff\xd8" + b"\xff" * 500_000))
    assert time.perf_counter() - started < 2
    assert report.detected_type == "jpeg"


def test_corrupt_lzma_member_is_a_clean_error(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_LZMA) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<w:document>" + b"hello world " * 200 + b"</w:document>")
    data = bytearray(buffer.getvalue())
    entry = zipfile.ZipFile(io.BytesIO(bytes(data))).getinfo("word/document.xml")
    offset = entry.header_offset + 30 + len(entry.filename.encode()) + 4 + 4   # past the local header + LZMA props
    data[offset:offset + 16] = b"\xff" * 16
    report = analyse_file(write(tmp_path, "a.docx", bytes(data)))   # must not raise
    assert report.detected_type == "docx"
    assert "unreadable_part" in rules(report)
