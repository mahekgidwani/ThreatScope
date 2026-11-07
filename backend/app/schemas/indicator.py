from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.enums import IndicatorType


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: IndicatorType
    value: str
    first_seen: datetime
    last_seen: datetime
    sighting_count: int
