"""List, read, create and update incidents. An incident groups existing events; its severity and risk score are
taken from them (the highest severity, the highest event risk score), so no second scoring formula exists."""
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.enums import IncidentStatus, Severity
from app.errors import InvalidFilterError, NotFoundError
from app.models import Event, Incident, IncidentEvent
from app.models.types import utc_now
from app.schemas.incident import IncidentIn, IncidentPatch
from app.services.paging import check_paging

_SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(Severity)}


def list_incidents(db: Session, status: IncidentStatus | str | None,
                   limit: int, offset: int) -> tuple[list[Incident], int]:
    """Newest first."""
    check_paging(limit, offset)
    conditions = []
    if status is not None:
        try:
            conditions.append(Incident.status == IncidentStatus(status).value)
        except ValueError:
            raise InvalidFilterError("unknown incident status") from None
    total = db.scalar(select(func.count()).select_from(Incident).where(*conditions))
    page = db.scalars(select(Incident).where(*conditions)
                      .order_by(Incident.created_at.desc(), Incident.id.desc())
                      .limit(limit).offset(offset)).all()
    return list(page), total


def get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise NotFoundError("Incident")
    return incident


def incident_events(db: Session, incident_id: int) -> list[Event]:
    """The events of an incident, newest first, with their indicators."""
    return list(db.scalars(
        select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .options(selectinload(Event.indicators))
        .order_by(Event.occurred_at.desc(), Event.id.desc())
        .execution_options(populate_existing=True)))


def _load_events(db: Session, ids: list[uuid.UUID]) -> list[Event]:
    unique = list(dict.fromkeys(ids))
    found = {e.id: e for e in db.scalars(select(Event).where(Event.id.in_(unique)))}
    if len(found) != len(unique):
        raise NotFoundError("Event")
    return [found[i] for i in unique]


def _roll_up(incident: Incident, events: list[Event]) -> None:
    incident.severity = max((e.severity for e in events), key=_SEVERITY_RANK.__getitem__)
    incident.risk_score = max(e.risk_score for e in events)


def create_incident(db: Session, data: IncidentIn) -> Incident:
    events = _load_events(db, data.event_ids)
    incident = Incident(title=data.title, summary=data.summary, status=IncidentStatus.open.value, severity="info")
    _roll_up(incident, events)
    incident.events = events
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def update_incident(db: Session, incident_id: int, patch: IncidentPatch) -> Incident:
    incident = get_incident(db, incident_id)
    if patch.title is not None:
        incident.title = patch.title
    if patch.status is not None:
        incident.status = patch.status.value
    if "summary" in patch.model_fields_set:
        incident.summary = patch.summary
    if patch.add_event_ids or patch.remove_event_ids:
        members = {e.id: e for e in incident_events(db, incident_id)}
        if patch.add_event_ids:
            members.update({e.id: e for e in _load_events(db, patch.add_event_ids)})
        for event_id in patch.remove_event_ids:
            members.pop(event_id, None)
        if not members:
            raise InvalidFilterError("an incident must keep at least one event")
        incident.events = list(members.values())
        _roll_up(incident, list(members.values()))
        incident.updated_at = utc_now()   # membership alone changes no incident column
    db.commit()
    db.refresh(incident)
    return incident
