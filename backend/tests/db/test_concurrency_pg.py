"""Races that only a real multi-connection database can show. PostgreSQL only."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.errors import DuplicateEventError
from app.models import Event, EventIndicator, Indicator
from app.schemas.event import EventIn
from app.services.event_service import create_event

pytestmark = pytest.mark.postgres

WORKERS = 8
BASE = dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z",
            severity="high", description="probe")


def payload(**over) -> EventIn:
    return EventIn(**{**BASE, **over})


def run_together(pg_engine, payloads):
    """Create one event per payload, each in its own session, all released at the same instant."""
    barrier = threading.Barrier(len(payloads))

    def worker(data):
        with Session(pg_engine) as session:
            barrier.wait(timeout=30)
            try:
                return "ok", create_event(session, data)
            except DuplicateEventError as exc:
                return "duplicate", exc.existing_id
            except Exception as exc:  # noqa: BLE001 - reported as a failure by the assertions
                return "error", repr(exc)

    with ThreadPoolExecutor(max_workers=len(payloads)) as pool:
        return list(pool.map(worker, payloads))


def count(pg_engine, model) -> int:
    with Session(pg_engine) as session:
        return session.scalar(select(func.count()).select_from(model))


def test_concurrent_duplicate_external_id_gives_one_success_and_clean_conflicts(pg_engine):
    results = run_together(pg_engine, [payload(external_event_id="same-id", source_ip="203.0.113.42")] * WORKERS)

    kinds = [kind for kind, _ in results]
    assert kinds.count("error") == 0, results
    assert kinds.count("ok") == 1 and kinds.count("duplicate") == WORKERS - 1
    winner = next(value for kind, value in results if kind == "ok")
    assert all(value == winner.id for kind, value in results if kind == "duplicate")
    assert count(pg_engine, Event) == 1
    with Session(pg_engine) as session:       # losers must not have counted their sighting
        assert session.scalar(select(Indicator.sighting_count)) == 1


def test_concurrent_events_sharing_an_indicator_lose_no_sightings(pg_engine):
    results = run_together(pg_engine, [payload(domain="shared.example") for _ in range(WORKERS)])

    assert [kind for kind, _ in results] == ["ok"] * WORKERS, results
    assert count(pg_engine, Event) == WORKERS
    with Session(pg_engine) as session:
        assert session.scalar(select(Indicator.sighting_count)) == WORKERS
    assert count(pg_engine, Indicator) == 1
    assert count(pg_engine, EventIndicator) == WORKERS
    # Each event saw a different number of earlier sightings, so the bonus schedule is exact even under a race.
    scores = sorted(event.risk_score for _, event in results)
    assert scores == [55 + b for b in (0, 5, 10, 15, 20, 20, 20, 20)]


def test_events_that_share_indicators_in_opposite_order_do_not_deadlock(pg_engine):
    a = payload(domain="one.example", url="http://two.example/x")   # touches one.example then two.example
    b = payload(domain="two.example", url="http://one.example/x")   # touches two.example then one.example
    results = run_together(pg_engine, [a, b] * (WORKERS // 2))

    assert [kind for kind, _ in results] == ["ok"] * WORKERS, results
    with Session(pg_engine) as session:
        counts = dict(session.execute(select(Indicator.value, Indicator.sighting_count).where(Indicator.type == "domain")).all())
    assert counts == {"one.example": WORKERS, "two.example": WORKERS}
