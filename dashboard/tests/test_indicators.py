from datetime import timedelta

import pytest

from tests.conftest import make_api
from tests.fake_backend import FakeBackend, T0, indicator
from ts_dashboard import components as c
from ts_dashboard import indicators as ix
from ts_dashboard.models import Indicator


def api_for(backend):
    return make_api(backend)[0]


def values(page) -> list[str]:
    return [i.value for i in page.items]


@pytest.fixture
def twelve():
    return FakeBackend(indicators=[indicator(n, "ip", f"10.0.0.{n}", sightings=(n % 4) + 1, last=T0 + timedelta(minutes=n)) for n in range(1, 13)])


def test_default_order_is_most_recently_seen_and_pages_do_not_overlap(twelve):
    api = api_for(twelve)
    first, second = (ix.fetch_indicator_page(api, None, None, p, 5) for p in (0, 1))
    assert values(first) == [f"10.0.0.{n}" for n in range(12, 7, -1)] and first.total == 12 and first.pages == 3
    assert set(values(first)).isdisjoint(values(second))
    last = ix.fetch_indicator_page(api, None, None, 2, 5)
    assert len(last.items) == 2 and (last.first_item, last.last_item) == (11, 12)


def test_most_sightings_sort_is_global_not_per_page(twelve):
    api = api_for(twelve)
    page = ix.fetch_indicator_page(api, None, None, 0, 4, "Most sightings")
    assert [i.sighting_count for i in page.items][:3] == [4, 4, 4]               # the three four-times-seen ones lead (a per-page sort could not do this)
    counts = [i.sighting_count for p in range(3) for i in ix.fetch_indicator_page(api, None, None, p, 4, "Most sightings").items]
    assert counts == sorted(counts, reverse=True) and len(counts) == 12
    assert page.sorted_over is None


def test_sort_over_a_capped_scan_says_so(twelve, monkeypatch):
    monkeypatch.setattr(ix, "SORT_SCAN", 5)
    page = ix.fetch_indicator_page(api_for(twelve), None, None, 0, 10, "Most sightings")
    assert page.sorted_over == 5 and page.total == 12


def test_newest_first_seen_sort():
    backend = FakeBackend(indicators=[{**indicator(1, value="old"), "first_seen": "2026-01-01T00:00:00Z"},
                                      {**indicator(2, "ip", "new"), "first_seen": "2026-06-01T00:00:00Z"}])
    assert values(ix.fetch_indicator_page(api_for(backend), None, None, 0, 10, "Newest first seen")) == ["new", "old"]


def test_type_and_value_filters_and_blank_value_is_ignored():
    backend = FakeBackend(indicators=[indicator(1, "ip", "1.1.1.1"), indicator(2, "domain", "a.example"), indicator(3, "sha256", "b" * 64)])
    api = api_for(backend)
    assert values(ix.fetch_indicator_page(api, "domain", None, 0, 10)) == ["a.example"]
    assert values(ix.fetch_indicator_page(api, None, "1.1.1.1", 0, 10)) == ["1.1.1.1"]
    assert ix.fetch_indicator_page(api, "url", None, 0, 10).total == 0
    assert ix.fetch_indicator_page(api, None, "   ", 0, 10).total == 3


def test_empty_and_out_of_range_pages(twelve):
    empty = ix.fetch_indicator_page(api_for(FakeBackend()), None, None, 4, 10)
    assert (empty.items, empty.total, empty.page, empty.pages) == ([], 0, 0, 1)
    assert ix.fetch_indicator_page(api_for(twelve), None, None, 99, 5).page == 2
    assert ix.fetch_indicator_page(api_for(twelve), None, None, -1, 5).page == 0


def test_tables_escape_and_label_types():
    hostile = Indicator.model_validate(indicator(1, "url", "http://x.example/<script>"))
    html = c.indicators_full_table([hostile])
    assert "URL" in html and "<script>" not in html and "&lt;script&gt;" in html and "First recorded" in html
    assert "(events that mentioned it" in c.indicator_detail(hostile) and "&lt;script&gt;" in c.indicator_detail(hostile)
