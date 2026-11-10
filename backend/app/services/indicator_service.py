from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.enums import IndicatorType
from app.errors import InvalidFilterError
from app.models import Indicator
from app.schemas.event import canonical_ip, normalise_domain
from app.services.paging import check_paging, check_text_filter


def list_indicators(db: Session, type: IndicatorType | str | None, value: str | None,
                    limit: int, offset: int) -> tuple[list[Indicator], int]:
    """Most recently seen first. `type` is an exact filter; `value` is an exact match, after
    normalisation for ip and domain (the same rules as ingestion and the events filters)."""
    check_paging(limit, offset)
    conditions = []
    kind = None
    if type is not None:
        try:
            kind = IndicatorType(type)
            conditions.append(Indicator.type == kind.value)
        except ValueError:
            raise InvalidFilterError("unknown indicator type") from None
    if value is not None:
        value = check_text_filter("value", value)
        normalise = {IndicatorType.ip: canonical_ip, IndicatorType.domain: normalise_domain}.get(kind)
        if normalise is not None:
            try:
                value = normalise(value)
            except ValueError:
                raise InvalidFilterError(f"value is not a valid {kind.value}") from None
        conditions.append(Indicator.value == value)
    total = db.scalar(select(func.count()).select_from(Indicator).where(*conditions))
    page = db.scalars(select(Indicator).where(*conditions)
                      .order_by(Indicator.last_seen.desc(), Indicator.id.desc())
                      .limit(limit).offset(offset)).all()
    return list(page), total
