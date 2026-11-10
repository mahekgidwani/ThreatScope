"""Data side of the Events Explorer: filters, the search box, time ranges, pages and related events.

Everything here is built on what `GET /api/v1/events` really offers: exact-match filters (source, severity,
event_type, source_ip, domain), start_time (inclusive) / end_time (exclusive), limit <= 100, and ONE order:
newest first. "Oldest first" is produced without fetching everything: page k from the old end is the
slice at offset `total - (k+1)*size`, reversed.
"""
import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.models import Event
from ts_dashboard.paging import fetch_up_to

PAGE_SIZES = (10, 25, 50, 100)
TYPE_SCAN = 500
RELATED_LIMIT = 10
RANGE_PRESETS = {"All time": None, "Last hour": timedelta(hours=1), "Last 24 hours": timedelta(hours=24),
                 "Last 7 days": timedelta(days=7), "Last 30 days": timedelta(days=30)}
RANGE_BUCKET = timedelta(minutes=5)     # relative ranges start on a multiple of this, so reruns build equal filters
CUSTOM_RANGE = "Custom (UTC dates)"
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HOST_CHARS = re.compile(r"[^\s/:@?#]+")


@dataclass(frozen=True)
class EventFilters:
    source: str | None = None
    severity: str | None = None
    event_type: str | None = None
    source_ip: str | None = None
    domain: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None

    def params(self) -> dict:
        return {k: v for k, v in vars(self).items() if v is not None}

    @property
    def active(self) -> bool:
        return bool(self.params())


@dataclass(frozen=True)
class SearchQuery:
    """What the search box text means. kind: 'empty', 'event_id', 'ip', 'domain' or 'unsupported'."""

    kind: str
    value: str = ""
    message: str = ""


def classify_search(text: str) -> SearchQuery:
    """The API can look an event up by id and filter by exact source IP or exact domain. Nothing else."""
    text = (text or "").strip()
    if not text:
        return SearchQuery("empty")
    try:
        return SearchQuery("event_id", str(UUID(text)))
    except ValueError:
        pass
    try:
        return SearchQuery("ip", str(ipaddress.ip_address(text)))
    except ValueError:
        pass
    if _HEX64.fullmatch(text) or "://" in text:
        return SearchQuery("unsupported", text, "The API cannot filter events by file hash or URL yet. "
                                                  "Search an event ID, a source IP address or a domain.")
    if _HOST_CHARS.fullmatch(text) and len(text) <= 253:
        return SearchQuery("domain", text.lower())
    return SearchQuery("unsupported", text, "Search an event ID, a source IP address or a domain (exact match).")


def time_range(preset: str, now: datetime, start_date=None, end_date=None) -> tuple[datetime | None, datetime | None]:
    """(start_time inclusive, end_time exclusive) in UTC. Custom dates are whole UTC days, end date included."""
    if preset == CUSTOM_RANGE:
        start = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc) if start_date else None
        end = datetime.combine(end_date + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc) if end_date else None
        return start, end
    span = RANGE_PRESETS.get(preset)
    if not span:
        return None, None
    # shortcut: a click that straddles a 5-minute boundary still resets paging once; anchor the time in session_state to fix.
    start = now - span
    return start - (start - datetime.min.replace(tzinfo=start.tzinfo)) % RANGE_BUCKET, None


@dataclass(frozen=True)
class EventPage:
    items: list[Event]
    total: int
    page: int          # zero-based, after clamping into range
    page_size: int
    ascending: bool

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / self.page_size))

    @property
    def first_item(self) -> int:
        return self.page * self.page_size + 1 if self.items else 0

    @property
    def last_item(self) -> int:
        return self.page * self.page_size + len(self.items)


def fetch_event_page(api: ThreatScopeApi, filters: EventFilters, page: int, page_size: int, ascending: bool = False) -> EventPage:
    """One page of matching events by occurrence time. A page number past the end (the data shrank, or a
    filter changed) is moved to the last page instead of showing nothing."""
    params = filters.params()
    total = api.list_events(**params, limit=1).total
    last = max(0, math.ceil(total / page_size) - 1)
    page = min(max(0, page), last)
    if not total:
        return EventPage([], 0, 0, page_size, ascending)
    if ascending:
        offset = max(0, total - (page + 1) * page_size)
        limit = min(page_size, total - page * page_size)
        items = list(reversed(api.list_events(**params, limit=limit, offset=offset).items))
    else:
        items = api.list_events(**params, limit=page_size, offset=page * page_size).items
    return EventPage(items, total, page, page_size, ascending)


def event_type_options(api: ThreatScopeApi) -> list[str]:
    """Event types seen in the newest TYPE_SCAN events (the API has no 'list types' call)."""
    events, _ = fetch_up_to(api.list_events, TYPE_SCAN)
    return sorted({e.event_type for e in events})


def related_events(api: ThreatScopeApi, event: Event) -> dict[str, list[Event]]:
    """Other events that share this event's source IP or domain, by the API's exact-match filters.
    (Events sharing only a URL or file hash cannot be asked for: the API has no such filter.)"""
    found: dict[str, list[Event]] = {}
    for label, key, value in (("source IP", "source_ip", event.source_ip), ("domain", "domain", event.domain)):
        if value:
            others = [e for e in api.list_events(**{key: value}, limit=RELATED_LIMIT + 1).items if e.id != event.id]
            found[f"{label} {value}"] = others[:RELATED_LIMIT]
    return found

