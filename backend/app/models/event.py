"""The `events` table: one row per security event, in the common ThreatScope format."""
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, Index, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.enums import Severity, Source
from app.models.types import JsonType, UtcDateTime, enum_check, utc_now


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        # Same source + same external id = the same event (duplicate protection).
        # Rows without an external id are never treated as duplicates (NULLs are distinct).
        UniqueConstraint("source", "external_event_id"),
        CheckConstraint(enum_check("source", Source), name="source_valid"),
        CheckConstraint(enum_check("severity", Severity), name="severity_valid"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        Index("ix_events_occurred_at", "occurred_at"),
        Index("ix_events_source_event_type", "source", "event_type"),
        Index("ix_events_severity", "severity"),
        Index("ix_events_source_ip", "source_ip"),
        Index("ix_events_domain", "domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    external_event_id: Mapped[str | None] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime)    # when it really happened
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)  # when we stored it
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    domain: Mapped[str | None] = mapped_column(String(253))
    url: Mapped[str | None] = mapped_column(String(1024))
    file_hash: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    description: Mapped[str] = mapped_column(String(2000))
    # The Python attribute can't be called `metadata` (reserved by SQLAlchemy); the column can.
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JsonType, default=dict)

    indicators: Mapped[list["Indicator"]] = relationship(  # noqa: F821
        secondary="event_indicators", back_populates="events", passive_deletes=True)
