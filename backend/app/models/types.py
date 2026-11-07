"""Column types and helpers shared by the models."""
from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import DateTime, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

# Plain JSON everywhere, binary JSONB (indexable, faster) on PostgreSQL.
JsonType = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator):
    """Timezone-aware datetimes, always UTC.

    Naive datetimes are refused. PostgreSQL returns aware values itself; SQLite drops the
    timezone, so UTC is re-attached when reading.
    """

    impl = DateTime
    cache_ok = True

    def __init__(self):
        super().__init__(timezone=True)

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime is not allowed; use a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def enum_check(column: str, enum_cls: type[StrEnum]) -> str:
    """SQL text for a CHECK that limits `column` to the values of `enum_cls`."""
    values = ", ".join(f"'{member.value}'" for member in enum_cls)
    return f"{column} IN ({values})"
