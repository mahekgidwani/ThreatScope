from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.enums import IncidentStatus, Severity


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int
    created_at: datetime
    updated_at: datetime
    summary: str | None = None
