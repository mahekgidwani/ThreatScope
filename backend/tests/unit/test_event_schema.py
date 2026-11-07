"""EventIn: strict validation and normalisation of everything a client can send."""
from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.config import get_settings
from app.schemas.event import EventIn, normalise_domain

BASE = dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
            severity="high", description="x")


def make(**over) -> EventIn:
    return EventIn(**{**BASE, **over})


def rejected(**over):
    with pytest.raises(ValidationError):
        make(**over)


# ---- basics --------------------------------------------------------------------

def test_valid_minimal_event():
    ev = make()
    assert ev.occurred_at.utcoffset() == timedelta(0)
    assert ev.metadata == {}
    assert ev.external_event_id is None and ev.domain is None and ev.url is None


@pytest.mark.parametrize("field", ["id", "received_at", "risk_score", "risk_factors", "foo"])
def test_server_owned_and_unknown_fields_are_rejected(field):
    rejected(**{field: 1})


@pytest.mark.parametrize("over", [{"source": "Honeypot"}, {"source": "email"}, {"severity": "HIGH"},
                                  {"severity": "urgent"}])
def test_enums_are_exact(over):
    rejected(**over)


def test_required_fields():
    for missing in ("source", "event_type", "occurred_at", "severity", "description"):
        data = {k: v for k, v in BASE.items() if k != missing}
        with pytest.raises(ValidationError):
            EventIn(**data)


@pytest.mark.parametrize("value", ["Bad Type!", "UPPER", "", "x" * 65, "has space"])
def test_event_type_rules(value):
    rejected(event_type=value)


@pytest.mark.parametrize("value", ["has space", "", "x" * 129, "semi;colon", "ünï"])
def test_external_event_id_rules(value):
    rejected(external_event_id=value)


def test_external_event_id_accepts_the_allowed_characters():
    assert make(external_event_id="Abc-123_x.y:z").external_event_id == "Abc-123_x.y:z"


@pytest.mark.parametrize("value", ["", "   ", "x" * 2001])
def test_description_required_and_bounded(value):
    rejected(description=value)


def test_description_boundary_2000_is_ok():
    assert len(make(description="x" * 2000).description) == 2000


# ---- timestamps ----------------------------------------------------------------

def test_naive_timestamp_rejected():
    rejected(occurred_at="2026-11-07T10:00:00")


def test_offset_is_converted_to_utc():
    ev = make(occurred_at="2026-11-07T15:30:00+05:30")
    assert (ev.occurred_at.hour, ev.occurred_at.minute) == (10, 0)
    assert ev.occurred_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize("value", [1700000000, 1700000000.5, "1700000000", "1700000000.5", "not a date", ""])
def test_epoch_numbers_and_garbage_are_rejected(value):
    rejected(occurred_at=value)


# ---- IP addresses --------------------------------------------------------------

def test_ip_addresses_are_stored_in_canonical_form():
    assert make(source_ip="2001:0DB8:0:0:0:0:0:1").source_ip == "2001:db8::1"
    assert make(destination_ip="203.0.113.7").destination_ip == "203.0.113.7"


@pytest.mark.parametrize("value", ["999.1.1.1", "1.2.3", "abc", "", "1.2.3.4/24", "203.0.113.7 "])
def test_invalid_ip_rejected(value):
    rejected(source_ip=value)


# ---- domains -------------------------------------------------------------------

def test_unicode_domain_becomes_punycode_lowercase_without_trailing_dot():
    assert make(domain="Bücher.Example.").domain == "xn--bcher-kva.example"


def test_cyrillic_homograph_domain_becomes_punycode():
    ev = make(domain="аpple.com")  # first letter is Cyrillic 'а', not Latin 'a'
    assert ev.domain.startswith("xn--")
    assert ev.domain != "apple.com"


def test_plain_domain_is_lowercased():
    assert make(domain="Evil.EXAMPLE.com").domain == "evil.example.com"


@pytest.mark.parametrize("value", [
    "bad_domain!.com", "a" * 64 + ".com", "", ".", "-bad.com", "bad-.com", "a..b.com",
    "x" * 250 + ".com", "with space.com", "1.2.3.4", "2001:db8::1",
])
def test_invalid_domain_rejected(value):
    rejected(domain=value)


def test_domain_length_boundary_is_253():
    ok = ".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 61])
    assert len(ok) == 253 and make(domain=ok).domain == ok
    rejected(domain=ok + "a")  # 254


def test_normalise_domain_is_reusable_and_idempotent():
    once = normalise_domain("BÜCHER.example")
    assert once == "xn--bcher-kva.example"
    assert normalise_domain(once) == once
    with pytest.raises(ValueError):
        normalise_domain("bad_domain!.com")


# ---- URLs ----------------------------------------------------------------------

@pytest.mark.parametrize("value", ["http://evil.example/a?q=1", "https://evil.example", "ftp://files.example/x"])
def test_url_accepted_and_unchanged(value):
    assert make(url=value).url == value


@pytest.mark.parametrize("value", [
    "javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "http://", "http:///path",
    "http://exämple.com/", "http://evil.example/ü", "http://evil.example/a b",
    "http://evil.example/\n", "evil.example/a", "", "http://" + "a" * 1030 + ".com",
])
def test_url_rejected(value):
    rejected(url=value)


def test_url_length_boundary_is_1024():
    prefix = "http://evil.example/"
    assert len(make(url=prefix + "a" * (1024 - len(prefix))).url) == 1024
    rejected(url=prefix + "a" * (1025 - len(prefix)))


# ---- file hash -----------------------------------------------------------------

def test_file_hash_is_lowercased():
    assert make(file_hash="AB" * 32).file_hash == "ab" * 32


@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "g" * 64, "", "a" * 63 + " "])
def test_file_hash_rejected(value):
    rejected(file_hash=value)


# ---- metadata ------------------------------------------------------------------

def test_metadata_accepts_nested_json():
    meta = {"rule": "9500001", "tags": ["xss"], "nested": {"ok": True, "n": 1.5, "none": None}}
    assert make(metadata=meta).metadata == meta


def test_metadata_too_large_rejected():
    rejected(metadata={"k": "x" * 70000})


def test_metadata_size_boundary_is_exact():
    cap = get_settings().max_metadata_bytes
    overhead = len('{"k":""}')
    assert make(metadata={"k": "x" * (cap - overhead)})            # exactly cap bytes
    rejected(metadata={"k": "x" * (cap - overhead + 1)})           # one byte over


def test_metadata_size_is_counted_in_bytes_not_characters():
    cap = get_settings().max_metadata_bytes
    chars = cap // 3 + 1                       # fewer characters than the cap, but > cap bytes
    rejected(metadata={"k": "値" * chars})


@pytest.mark.parametrize("meta", [{"when": object()}, {"x": float("nan")}, {"x": float("inf")}])
def test_metadata_must_be_plain_json(meta):
    rejected(metadata=meta)


def nested(levels: int) -> dict:
    """A dict nested `levels` containers deep: nested(1) == {}, nested(2) == {"n": {}} ..."""
    result: dict = {}
    for _ in range(levels - 1):
        result = {"n": result}
    return result


def test_metadata_nesting_depth_boundary_is_10():
    assert make(metadata=nested(10))
    rejected(metadata=nested(11))
    assert make(metadata={"a": [[[{"b": 1}]]]})  # lists count as levels too (depth 5)
    rejected(metadata={"a": [[[[[[[[[[1]]]]]]]]]]})  # 11 levels with lists


def test_metadata_absurd_nesting_is_rejected_cleanly():
    rejected(metadata=nested(5000))


def test_metadata_self_referencing_structure_is_rejected_not_looped():
    loop: dict = {}
    loop["me"] = loop
    rejected(metadata=loop)


@pytest.mark.parametrize("meta", [None, [], "text", 5])
def test_metadata_must_be_an_object(meta):
    rejected(metadata=meta)
