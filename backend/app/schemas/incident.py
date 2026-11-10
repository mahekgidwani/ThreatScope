from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.enums import IncidentStatus, Severity
from app.schemas.event import EventOut

MAX_TITLE = 200
MAX_SUMMARY = 5000
MAX_EVENTS_PER_REQUEST = 100


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
    event_count: int = 0

    @field_validator("event_count", mode="before")
    @classmethod
    def _unloaded_count_is_zero(cls, value: int | None) -> int:
        return 0 if value is None else value  # a never-stored Incident has no count yet


class IncidentDetailOut(IncidentOut):
    """An incident with the events it groups, newest first."""

    events: list[EventOut] = Field(default_factory=list)


def _clean_text(value: str, name: str, limit: int, required: bool) -> str:
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL characters")  # PostgreSQL cannot store them
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} contains characters that cannot be stored") from None
    value = value.strip()
    if required and not value:
        raise ValueError(f"{name} must not be blank")
    if len(value) > limit:
        raise ValueError(f"{name} must be at most {limit} characters")
    return value


class IncidentIn(BaseModel):
    """Create an incident from existing events. Severity and risk are NOT accepted: they are taken from the events."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(max_length=MAX_TITLE)
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY)
    event_ids: list[UUID] = Field(min_length=1, max_length=MAX_EVENTS_PER_REQUEST)

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _clean_text(value, "title", MAX_TITLE, required=True)

    @field_validator("summary")
    @classmethod
    def _summary(cls, value: str | None) -> str | None:
        return None if value is None else (_clean_text(value, "summary", MAX_SUMMARY, required=False) or None)


class IncidentPatch(BaseModel):
    """Change an incident. Only the fields sent change; `summary: ""` or null clears the notes."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, max_length=MAX_TITLE)
    status: IncidentStatus | None = None
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY)
    add_event_ids: list[UUID] = Field(default_factory=list, max_length=MAX_EVENTS_PER_REQUEST)
    remove_event_ids: list[UUID] = Field(default_factory=list, max_length=MAX_EVENTS_PER_REQUEST)

    @field_validator("title")
    @classmethod
    def _title(cls, value: str | None) -> str | None:
        return None if value is None else _clean_text(value, "title", MAX_TITLE, required=True)

    @field_validator("summary")
    @classmethod
    def _summary(cls, value: str | None) -> str | None:
        return None if value is None else (_clean_text(value, "summary", MAX_SUMMARY, required=False) or None)

    @model_validator(mode="after")
    def _something_to_change(self) -> "IncidentPatch":
        sent = self.model_fields_set
        if not (sent & {"title", "status", "summary"}) and not self.add_event_ids and not self.remove_event_ids:
            raise ValueError("send at least one field to change")
        if "title" in sent and self.title is None:
            raise ValueError("title cannot be cleared")
        if "status" in sent and self.status is None:
            raise ValueError("status cannot be cleared")
        if set(self.add_event_ids) & set(self.remove_event_ids):
            raise ValueError("an event cannot be both added and removed")
        return self
