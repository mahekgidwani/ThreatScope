"""Data side of the Indicator Explorer.

`GET /api/v1/indicators` filters by type and exact value and returns most recently seen first. "Most sightings
first" is not an API order, so that sort reads up to SORT_SCAN indicators and sorts them here (and says so when
there are more).
"""
import math
from dataclasses import dataclass

from ts_dashboard.api_client import ThreatScopeApi
from ts_dashboard.models import Indicator
from ts_dashboard.paging import fetch_up_to

PAGE_SIZES = (10, 25, 50, 100)
SORT_SCAN = 1000
SORTS = ("Most recently seen", "Most sightings", "Newest first seen")


@dataclass(frozen=True)
class IndicatorPage:
    items: list[Indicator]
    total: int
    page: int
    page_size: int
    sort: str
    sorted_over: int | None = None    # set when sorting only covered the first SORT_SCAN of `total`

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / self.page_size))

    @property
    def first_item(self) -> int:
        return self.page * self.page_size + 1 if self.items else 0

    @property
    def last_item(self) -> int:
        return self.page * self.page_size + len(self.items)


def fetch_indicator_page(api: ThreatScopeApi, indicator_type: str | None, value: str | None, page: int, page_size: int,
                         sort: str = SORTS[0]) -> IndicatorPage:
    value = (value or "").strip() or None
    first = api.list_indicators(indicator_type=indicator_type, value=value, limit=1)
    total = first.total
    page = min(max(0, page), max(0, math.ceil(total / page_size) - 1))
    if not total:
        return IndicatorPage([], 0, 0, page_size, sort)
    if sort == SORTS[0]:
        items = api.list_indicators(indicator_type=indicator_type, value=value, limit=page_size, offset=page * page_size).items
        return IndicatorPage(items, total, page, page_size, sort)
    everything, _ = fetch_up_to(api.list_indicators, SORT_SCAN, indicator_type=indicator_type, value=value)
    key = ((lambda i: (-i.sighting_count, -i.last_seen.timestamp(), i.value)) if sort == SORTS[1]
           else (lambda i: (-i.first_seen.timestamp(), i.value)))
    ordered = sorted(everything, key=key)
    return IndicatorPage(ordered[page * page_size:(page + 1) * page_size], total, page, page_size, sort,
                         sorted_over=len(everything) if len(everything) < total else None)
