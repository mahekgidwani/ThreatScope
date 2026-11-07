from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.enums import IndicatorType
from app.errors import InvalidFilterError
from app.models import Indicator
from app.services.paging import check_paging


def list_indicators(db: Session, type: IndicatorType | str | None, value: str | None,
                    limit: int, offset: int) -> tuple[list[Indicator], int]:
    """Most recently seen first. `type` and `value` are exact-match filters."""
    check_paging(limit, offset)
    conditions = []
    if type is not None:
        try:
            conditions.append(Indicator.type == IndicatorType(type).value)
        except ValueError:
            raise InvalidFilterError("unknown indicator type") from None
    if value is not None:
        conditions.append(Indicator.value == value)
    total = db.scalar(select(func.count()).select_from(Indicator).where(*conditions))
    page = db.scalars(select(Indicator).where(*conditions)
                      .order_by(Indicator.last_seen.desc(), Indicator.id.desc())
                      .limit(limit).offset(offset)).all()
    return list(page), total
