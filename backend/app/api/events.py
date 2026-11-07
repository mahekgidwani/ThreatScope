from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_api_key
from app.db import get_db
from app.enums import Severity, Source
from app.schemas.common import Page
from app.schemas.event import EventIn, EventOut
from app.services.event_service import EventFilters, create_event, get_event, list_events
from app.services.paging import DEFAULT_LIMIT, MAX_LIMIT

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", status_code=201, response_model=EventOut, dependencies=[Depends(require_api_key)],
             summary="Ingest one event (needs the X-API-Key header)")
def post_event(data: EventIn, db: Session = Depends(get_db)):
    return EventOut.model_validate(create_event(db, data))


@router.get("", response_model=Page[EventOut], summary="List events, newest first")
def get_events(
    source: Source | None = None,
    event_type: str | None = None,
    severity: Severity | None = None,
    source_ip: str | None = None,
    domain: str | None = None,
    start_time: datetime | None = Query(None, description="Inclusive. Must include a timezone."),
    end_time: datetime | None = Query(None, description="Exclusive. Must include a timezone."),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    filters = EventFilters(source=source, event_type=event_type, severity=severity, source_ip=source_ip,
                           domain=domain, start_time=start_time, end_time=end_time)
    events, total = list_events(db, filters, limit, offset)
    return Page[EventOut](items=[EventOut.model_validate(e) for e in events],
                          total=total, limit=limit, offset=offset)


@router.get("/{event_id}", response_model=EventOut, summary="One event with its indicators")
def get_one_event(event_id: UUID, db: Session = Depends(get_db)):
    return EventOut.model_validate(get_event(db, event_id))
