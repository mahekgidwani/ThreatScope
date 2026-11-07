"""`indicators` (unique IPs, domains, URLs, hashes seen) and the `event_indicators` link table."""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.enums import IndicatorType
from app.models.types import UtcDateTime, enum_check, utc_now


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value"),
        CheckConstraint(enum_check("type", IndicatorType), name="type_valid"),
        CheckConstraint("sighting_count >= 1", name="sighting_count_min"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(1024))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1)

    events: Mapped[list["Event"]] = relationship(  # noqa: F821
        secondary="event_indicators", back_populates="indicators", passive_deletes=True)


class EventIndicator(Base):
    """Says "this event mentioned this indicator". The composite key forbids duplicate links."""

    __tablename__ = "event_indicators"
    __table_args__ = (Index("ix_event_indicators_indicator_id", "indicator_id"),)

    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
