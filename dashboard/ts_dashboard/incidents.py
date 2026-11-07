"""Data side of Incident Management: counts by status, pages, and reading event IDs a person typed or pasted."""
import math
import re
from dataclasses import dataclass
from uuid import UUID

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.models import INCIDENT_STATUSES, Incident

PAGE_SIZES = (10, 25, 50)
MAX_EVENT_IDS = 100                      # the API's limit per request
STATUS_LABELS = {"open": "Open", "investigating": "Investigating", "closed": "Closed"}
_SPLIT = re.compile(r"[\s,;]+")


def status_counts(api: ThreatScopeApi) -> dict[str, int]:
    """Exact count per status (the `total` of a `limit=1` query each), plus 'all'."""
    counts = {s: api.list_incidents(status=s, limit=1).total for s in INCIDENT_STATUSES}
    counts["all"] = api.list_incidents(limit=1).total
    return counts


@dataclass(frozen=True)
class IncidentPage:
    items: list[Incident]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / self.page_size))

    @property
    def first_item(self) -> int:
        return self.page * self.page_size + 1 if self.items else 0

    @property
    def last_item(self) -> int:
        return self.page * self.page_size + len(self.items)


def fetch_incident_page(api: ThreatScopeApi, status: str | None, page: int, page_size: int) -> IncidentPage:
    total = api.list_incidents(status=status, limit=1).total
    page = min(max(0, page), max(0, math.ceil(total / page_size) - 1))
    if not total:
        return IncidentPage([], 0, 0, page_size)
    items = api.list_incidents(status=status, limit=page_size, offset=page * page_size).items
    return IncidentPage(items, total, page, page_size)


def parse_event_ids(text: str) -> tuple[list[str], list[str]]:
    """Event IDs from pasted text (separated by spaces, commas, semicolons or new lines).
    Returns (valid ids in order without duplicates, the pieces that are not event IDs)."""
    valid: list[str] = []
    invalid: list[str] = []
    for piece in filter(None, _SPLIT.split(text or "")):
        try:
            event_id = str(UUID(piece))
        except ValueError:
            invalid.append(piece[:40])
            continue
        if event_id not in valid:
            valid.append(event_id)
    return valid, invalid


def default_title(indicator_type: str, value: str) -> str:
    label = {"ip": "IP address", "domain": "domain", "url": "URL", "sha256": "file hash"}.get(indicator_type, indicator_type)
    return f"Events sharing {label} {value if len(value) <= 60 else value[:59] + '…'}"
