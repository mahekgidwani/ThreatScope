from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.orm import Session

from app.api.deps import require_api_key
from app.db import get_db
from app.enums import IncidentStatus
from app.models import Incident
from app.schemas.common import Page
from app.schemas.event import EventOut
from app.schemas.incident import IncidentDetailOut, IncidentIn, IncidentOut, IncidentPatch
from app.services.incident_service import (
    create_incident, get_incident, incident_events, list_incidents, update_incident,
)
from app.services.paging import DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

# The id column is a 4-byte integer: a larger value would be a database error (500), not a 404.
IncidentId = Path(ge=1, le=2_147_483_647)


@router.get("", response_model=Page[IncidentOut], summary="List incidents, newest first")
def get_incidents(
    status: IncidentStatus | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
    db: Session = Depends(get_db),
):
    items, total = list_incidents(db, status, limit, offset)
    return Page[IncidentOut](items=[IncidentOut.model_validate(i) for i in items],
                             total=total, limit=limit, offset=offset)


def _detail(db: Session, incident: Incident) -> IncidentDetailOut:
    detail = IncidentDetailOut.model_validate(incident)
    detail.events = [EventOut.model_validate(e) for e in incident_events(db, incident.id)]
    return detail


@router.get("/{incident_id}", response_model=IncidentDetailOut, summary="One incident with its events")
def get_one_incident(incident_id: int = IncidentId, db: Session = Depends(get_db)):
    return _detail(db, get_incident(db, incident_id))


@router.post("", status_code=201, response_model=IncidentDetailOut, dependencies=[Depends(require_api_key)],
             summary="Group existing events into an incident (needs the X-API-Key header)")
def post_incident(data: IncidentIn, db: Session = Depends(get_db)):
    return _detail(db, create_incident(db, data))


@router.patch("/{incident_id}", response_model=IncidentDetailOut, dependencies=[Depends(require_api_key)],
              summary="Change an incident's status, title, notes or events (needs the X-API-Key header)")
def patch_incident(data: IncidentPatch, incident_id: int = IncidentId, db: Session = Depends(get_db)):
    return _detail(db, update_incident(db, incident_id, data))
