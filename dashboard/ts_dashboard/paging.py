"""Collect more than one API page (the API caps `limit` at 100)."""
from typing import Callable, TypeVar

from ts_dashboard.models import Page

T = TypeVar("T")
PAGE_SIZE = 100  # the API's maximum


def fetch_up_to(fetch: Callable[..., Page[T]], max_items: int, **filters) -> tuple[list[T], int]:
    """Read pages with `fetch(limit=..., offset=..., **filters)` until `max_items` are held or the data ends.

    Returns (items, total) where `total` is the API's count of ALL matches, so a caller can tell the list
    was cut short (`len(items) < total`) and say so instead of presenting a sample as everything.
    """
    items: list[T] = []
    total = 0
    while len(items) < max_items:
        page = fetch(limit=min(PAGE_SIZE, max_items - len(items)), offset=len(items), **filters)
        total = page.total
        items.extend(page.items)
        if not page.items or not page.has_next:
            break
    return items[:max_items], total
