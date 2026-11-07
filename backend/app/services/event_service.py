"""Store, fetch and list events.

`create_event` does everything for one event inside ONE database transaction:
  1. insert the event (the unique key on source + external_event_id rejects duplicates here),
  2. count a sighting for each of its indicators,
  3. score it, link the indicators, commit.
If anything fails, everything is rolled back.
"""
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.enums import IndicatorType, Severity, Source
from app.errors import DuplicateEventError, InvalidFilterError, NotFoundError
from app.models import Event, EventIndicator, Indicator
from app.models.types import utc_now
from app.schemas.event import EventIn, canonical_ip, normalise_domain
from app.services.indicator_extractor import extract_indicators
from app.services.paging import check_paging, check_text_filter
from app.services.risk_scoring import compute_risk

logger = logging.getLogger(__name__)


def _record_sighting(db: Session, kind: IndicatorType, value: str, now: datetime) -> tuple[int, int]:
    """Count one more sighting of an indicator. Returns (indicator id, sightings including this one).

    The increment is a single `UPDATE ... SET sighting_count = sighting_count + 1`, so two
    requests can never overwrite each other's count (no read-then-write). If the indicator
    does not exist yet it is inserted inside a SAVEPOINT: when another request inserts it first,
    only the savepoint is rolled back and we count our sighting on the row that now exists.
    """
    table = Indicator.__table__
    for _ in range(3):
        row = db.execute(
            update(table)
            .where(table.c.type == kind.value, table.c.value == value)
            .values(sighting_count=table.c.sighting_count + 1, last_seen=now)
            .returning(table.c.id, table.c.sighting_count)
        ).first()
        if row is not None:
            return row.id, row.sighting_count
        try:
            with db.begin_nested():
                indicator = Indicator(type=kind.value, value=value, first_seen=now, last_seen=now,
                                      sighting_count=1)
                db.add(indicator)
                db.flush()
            return indicator.id, 1
        except IntegrityError:
            continue  # lost the race to create it; loop and count on the existing row
    raise RuntimeError("could not record indicator sighting")


def _existing_event_id(db: Session, data: EventIn) -> uuid.UUID | None:
    if data.external_event_id is None:
        return None
    return db.scalar(select(Event.id).where(Event.source == data.source.value,
                                            Event.external_event_id == data.external_event_id))


def create_event(db: Session, data: EventIn) -> Event:
    """Validate-already-done `data` -> stored, scored event (with its indicators). Commits."""
    now = utc_now()
    event = Event(
        id=uuid.uuid4(), external_event_id=data.external_event_id, source=data.source.value,
        event_type=data.event_type, occurred_at=data.occurred_at, received_at=now,
        source_ip=data.source_ip, destination_ip=data.destination_ip, domain=data.domain,
        url=data.url, file_hash=data.file_hash, severity=data.severity.value,
        description=data.description, event_metadata=data.metadata, risk_score=0, risk_factors=[],
    )
    try:
        db.add(event)
        try:
            db.flush()  # duplicates are rejected here by the unique constraint
        except IntegrityError:
            db.rollback()
            existing_id = _existing_event_id(db, data)
            if existing_id is None:
                raise  # not a duplicate: a genuine integrity problem must not be disguised
            raise DuplicateEventError(existing_id) from None

        # Fixed (type, value) order: concurrent requests always lock shared indicators in the
        # same order, which rules out deadlocks.
        wanted = sorted(extract_indicators(data), key=lambda item: (item[0].value, item[1]))
        sightings = [_record_sighting(db, kind, value, now) for kind, value in wanted]

        # Sightings include this event; the bonus counts only EARLIER ones, hence the minus 1.
        prior_sightings = max((count for _, count in sightings), default=1) - 1
        event.risk_score, event.risk_factors = compute_risk(data.severity, data.source, prior_sightings)

        db.add_all(EventIndicator(event_id=event.id, indicator_id=indicator_id)
                   for indicator_id, _ in sightings)
        db.commit()
    except Exception:
        db.rollback()
        raise

    logger.info("event stored id=%s source=%s type=%s severity=%s risk=%s",
                event.id, data.source.value, data.event_type, data.severity.value, event.risk_score)
    return get_event(db, event.id)


def get_event(db: Session, event_id: uuid.UUID) -> Event:
    """One event with its indicators, freshly read from the database."""
    event = db.scalars(
        select(Event).where(Event.id == event_id)
        .options(selectinload(Event.indicators))
        .execution_options(populate_existing=True)
    ).one_or_none()
    if event is None:
        raise NotFoundError("event")
    return event


@dataclass(frozen=True)
class EventFilters:
    source: Source | None = None
    event_type: str | None = None
    severity: Severity | None = None
    source_ip: str | None = None
    domain: str | None = None
    start_time: datetime | None = None   # inclusive
    end_time: datetime | None = None     # exclusive


def _conditions(f: EventFilters) -> list:
    """Turn filters into exact-match conditions. Raises InvalidFilterError for unusable values."""
    conditions = []
    try:
        if f.source is not None:
            conditions.append(Event.source == Source(f.source).value)
        if f.severity is not None:
            conditions.append(Event.severity == Severity(f.severity).value)
    except ValueError:
        raise InvalidFilterError("unknown source or severity") from None
    if f.event_type is not None:
        conditions.append(Event.event_type == check_text_filter("event_type", f.event_type))  # exact, never LIKE
    if f.source_ip is not None:
        try:
            conditions.append(Event.source_ip == canonical_ip(f.source_ip))   # same rules as ingestion
        except ValueError:
            raise InvalidFilterError("source_ip is not a valid IP address") from None
    if f.domain is not None:
        try:
            conditions.append(Event.domain == normalise_domain(f.domain))   # same rules as ingestion
        except ValueError:
            raise InvalidFilterError("domain is not a valid hostname") from None
    start = _utc_filter_time("start_time", f.start_time)
    end = _utc_filter_time("end_time", f.end_time)
    if start is not None and end is not None and start > end:
        raise InvalidFilterError("start_time must not be after end_time")
    if start is not None:
        conditions.append(Event.occurred_at >= start)
    if end is not None:
        conditions.append(Event.occurred_at < end)
    return conditions


def _utc_filter_time(name: str, value: datetime | None) -> datetime | None:
    """A filter time as UTC. Needs a timezone; refuses values that fall outside years 1-9999 in UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise InvalidFilterError(f"{name} must include a timezone")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:
        raise InvalidFilterError(f"{name} is outside the supported date range") from None


def list_events(db: Session, filters: EventFilters, limit: int, offset: int) -> tuple[list[Event], int]:
    """Newest first (ties broken by id, so paging is stable). Returns (page, total matches)."""
    check_paging(limit, offset)
    conditions = _conditions(filters)
    total = db.scalar(select(func.count()).select_from(Event).where(*conditions))
    page = db.scalars(
        select(Event).where(*conditions)
        .options(selectinload(Event.indicators))
        .order_by(Event.occurred_at.desc(), Event.id.desc())
        .limit(limit).offset(offset)
        .execution_options(populate_existing=True)
    ).all()
    return list(page), total
