from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.enums import IncidentStatus
from app.errors import InvalidFilterError
from app.models import Incident
from app.services.paging import check_paging


def list_incidents(db: Session, status: IncidentStatus | str | None,
                   limit: int, offset: int) -> tuple[list[Incident], int]:
    """Newest first. Incidents are created by the correlation logic in Phase 4; until then this is empty."""
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
