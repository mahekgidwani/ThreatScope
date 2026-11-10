"""Decide which indicators (things worth correlating) one event mentions. Pure logic, no database."""
from urllib.parse import urlsplit

from app.enums import IndicatorType, Source
from app.schemas.event import EventIn, canonical_ip, normalise_domain

Indicator = tuple[IndicatorType, str]


def _host_indicator(url: str) -> Indicator | None:
    """The host part of a URL as an `ip` or `domain` indicator, or None if it is neither."""
    host = urlsplit(url).hostname  # lower-cased; no user:password, port or [] brackets
    if not host:
        return None
    try:
        return IndicatorType.ip, canonical_ip(host)
    except ValueError:
        pass
    try:
        return IndicatorType.domain, normalise_domain(host)
    except ValueError:
        return None  # e.g. an underscore name: keep the URL indicator, skip the host


def extract_indicators(event: EventIn) -> list[Indicator]:
    """Return the event's indicators in a stable order, each listed once.

    Order: source IP, destination IP, domain, URL, URL host, file hash.
    The destination IP counts only for `network` events. For honeypot events it is our own
    address; treating it as an indicator would link every attack to every other attack.
    """
    found: list[Indicator] = []

    if event.source_ip:
        found.append((IndicatorType.ip, event.source_ip))
    if event.destination_ip and event.source == Source.network:
        found.append((IndicatorType.ip, event.destination_ip))
    if event.domain:
        found.append((IndicatorType.domain, event.domain))
    if event.url:
        found.append((IndicatorType.url, event.url))
        host = _host_indicator(event.url)
        if host:
            found.append(host)
    if event.file_hash:
        found.append((IndicatorType.sha256, event.file_hash))

    return list(dict.fromkeys(found))  # drop duplicates, keep first-seen order
