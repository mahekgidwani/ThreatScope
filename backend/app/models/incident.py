"""`incidents` (groups of related events) and the `incident_events` link table.

Rows are created by the correlation logic in Phase 4; Phase 2 only provides the tables.
"""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.enums import IncidentStatus, Severity
from app.models.types import UtcDateTime, enum_check, utc_now


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(enum_check("status", IncidentStatus), name="status_valid"),
        CheckConstraint(enum_check("severity", Severity), name="severity_valid"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        Index("ix_incidents_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default=IncidentStatus.open.value)
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)
    summary: Mapped[str | None] = mapped_column(Text)

    events: Mapped[list["Event"]] = relationship(  # noqa: F821
        secondary="incident_events", passive_deletes=True)


class IncidentEvent(Base):
    """Says "this event belongs to this incident". The composite key forbids duplicate links."""

    __tablename__ = "incident_events"
    __table_args__ = (Index("ix_incident_events_event_id", "event_id"),)

    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
