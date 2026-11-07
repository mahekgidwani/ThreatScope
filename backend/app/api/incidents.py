from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.enums import IncidentStatus
from app.schemas.common import Page
from app.schemas.incident import IncidentOut
from app.services.incident_service import list_incidents
from app.services.paging import DEFAULT_LIMIT, MAX_LIMIT

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("", response_model=Page[IncidentOut],
            summary="List incidents (empty until correlation arrives in Phase 4)")
def get_incidents(
    status: IncidentStatus | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    items, total = list_incidents(db, status, limit, offset)
    return Page[IncidentOut](items=[IncidentOut.model_validate(i) for i in items],
                             total=total, limit=limit, offset=offset)
