from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.enums import IndicatorType
from app.schemas.common import Page
from app.schemas.indicator import IndicatorOut
from app.services.indicator_service import list_indicators
from app.services.paging import DEFAULT_LIMIT, MAX_LIMIT

router = APIRouter(prefix="/api/v1/indicators", tags=["indicators"])


@router.get("", response_model=Page[IndicatorOut], summary="List indicators, most recently seen first")
def get_indicators(
    indicator_type: IndicatorType | None = Query(None, alias="type"),
    value: str | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    items, total = list_indicators(db, indicator_type, value, limit, offset)
    return Page[IndicatorOut](items=[IndicatorOut.model_validate(i) for i in items],
                              total=total, limit=limit, offset=offset)
