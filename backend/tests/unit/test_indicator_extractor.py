"""Which indicators (IPs, domains, URLs, hashes) does one event contribute?"""
import pytest

from app.enums import IndicatorType as T
from app.schemas.event import EventIn
from app.services.indicator_extractor import extract_indicators

HASH = "ab" * 32
BASE = dict(source="honeypot", event_type="probe", occurred_at="2026-11-07T10:00:00Z",
            severity="low", description="x")


def ev(**over) -> EventIn:
    return EventIn(**{**BASE, **over})


def test_event_without_indicator_fields_yields_nothing():
    assert extract_indicators(ev()) == []


def test_source_ip_is_an_indicator():
    assert extract_indicators(ev(source_ip="203.0.113.42")) == [(T.ip, "203.0.113.42")]


def test_honeypot_destination_ip_is_ignored_because_it_is_our_own_address():
    got = extract_indicators(ev(source_ip="203.0.113.42", destination_ip="198.51.100.9"))
    assert got == [(T.ip, "203.0.113.42")]


@pytest.mark.parametrize("source", ["honeypot", "domain", "file"])
def test_destination_ip_is_ignored_for_every_non_network_source(source):
    assert extract_indicators(ev(source=source, destination_ip="198.51.100.9")) == []


def test_network_event_includes_the_destination_ip():
    got = extract_indicators(ev(source="network", source_ip="10.0.0.5", destination_ip="198.51.100.9"))
    assert got == [(T.ip, "10.0.0.5"), (T.ip, "198.51.100.9")]


def test_same_ip_as_source_and_destination_is_listed_once():
    got = extract_indicators(ev(source="network", source_ip="10.0.0.5", destination_ip="10.0.0.5"))
    assert got == [(T.ip, "10.0.0.5")]


def test_domain_is_an_indicator_in_its_normalised_form():
    assert extract_indicators(ev(source="domain", domain="Bücher.Example")) == [(T.domain, "xn--bcher-kva.example")]


def test_url_adds_the_url_and_its_host_as_a_domain():
    got = extract_indicators(ev(url="http://evil.example/a?q=1"))
    assert got == [(T.url, "http://evil.example/a?q=1"), (T.domain, "evil.example")]


def test_url_host_equal_to_domain_is_listed_once():
    got = extract_indicators(ev(domain="evil.example", url="http://evil.example/a"))
    assert got == [(T.domain, "evil.example"), (T.url, "http://evil.example/a")]


def test_url_host_is_lowercased_and_userinfo_port_and_trailing_dot_are_ignored():
    got = extract_indicators(ev(url="https://user:pw@EVIL.Example.:8443/x"))
    assert got == [(T.url, "https://user:pw@EVIL.Example.:8443/x"), (T.domain, "evil.example")]


def test_url_with_an_ip_host_becomes_an_ip_indicator_not_a_domain():
    got = extract_indicators(ev(url="http://203.0.113.9/x"))
    assert got == [(T.url, "http://203.0.113.9/x"), (T.ip, "203.0.113.9")]


def test_url_with_an_ipv6_host_uses_the_canonical_ip():
    got = extract_indicators(ev(url="http://[2001:0DB8::1]:8080/x"))
    assert got == [(T.url, "http://[2001:0DB8::1]:8080/x"), (T.ip, "2001:db8::1")]


@pytest.mark.parametrize("url", ["http://[fe80::1%25eth0]/x", "http://[fe80::1%eth0]/"])
def test_url_host_with_scope_id_creates_no_ip_indicator(url):
    assert extract_indicators(ev(url=url)) == [(T.url, url)]


def test_url_host_ipv6_is_canonical():
    got = extract_indicators(ev(url="http://[2001:DB8::1]/"))
    assert got == [(T.url, "http://[2001:DB8::1]/"), (T.ip, "2001:db8::1")]


def test_url_ip_host_equal_to_source_ip_is_listed_once():
    got = extract_indicators(ev(source_ip="203.0.113.9", url="http://203.0.113.9/x"))
    assert got == [(T.ip, "203.0.113.9"), (T.url, "http://203.0.113.9/x")]


def test_url_host_that_is_not_a_valid_hostname_still_yields_the_url():
    got = extract_indicators(ev(url="http://_dmarc.example/x"))   # underscore: not a hostname
    assert got == [(T.url, "http://_dmarc.example/x")]


def test_file_hash_is_an_indicator():
    assert extract_indicators(ev(source="file", file_hash=HASH.upper())) == [(T.sha256, HASH)]


def test_order_is_stable_and_nothing_is_duplicated():
    got = extract_indicators(ev(source="network", source_ip="10.0.0.5", destination_ip="198.51.100.9",
                                domain="evil.example", url="http://evil.example/a", file_hash=HASH))
    assert got == [
        (T.ip, "10.0.0.5"), (T.ip, "198.51.100.9"), (T.domain, "evil.example"),
        (T.url, "http://evil.example/a"), (T.sha256, HASH),
    ]
    assert len(got) == len(set(got))
