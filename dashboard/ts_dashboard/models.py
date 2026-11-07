"""What the API sends back, as validated objects.

These mirror the API's JSON (`EventOut`, `IndicatorOut`, `IncidentOut`, `HealthOut`, `Page`) but are written
here on purpose: the dashboard must not import backend code. Unknown extra fields are ignored, so a
backend that adds a field does not break the dashboard; a missing or wrong-typed field does raise, and the
client reports that as an unusable answer instead of showing wrong data.
"""
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Source = Literal["domain", "honeypot", "file", "network"]
Severity = Literal["info", "low", "medium", "high", "critical"]
IndicatorType = Literal["ip", "domain", "url", "sha256"]
IncidentStatus = Literal["open", "investigating", "closed"]

SOURCES: tuple[str, ...] = Source.__args__
SEVERITIES: tuple[str, ...] = Severity.__args__          # lowest to highest
INDICATOR_TYPES: tuple[str, ...] = IndicatorType.__args__
INCIDENT_STATUSES: tuple[str, ...] = IncidentStatus.__args__

T = TypeVar("T")


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class RiskFactor(_Model):
    rule: str
    points: int


class Indicator(_Model):
    id: int
    type: IndicatorType
    value: str
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    sighting_count: int = Field(ge=0)


class Event(_Model):
    id: UUID
    external_event_id: str | None = None
    source: Source
    event_type: str
    occurred_at: AwareDatetime
    received_at: AwareDatetime
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    indicators: list[Indicator] = Field(default_factory=list)


class Incident(_Model):
    id: int
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    created_at: AwareDatetime
    updated_at: AwareDatetime
    summary: str | None = None


class Page(_Model, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)

    @property
    def has_next(self) -> bool:
        return self.offset + len(self.items) < self.total


class ApiHealth(_Model):
    status: Literal["up"]


class DatabaseHealth(_Model):
    status: Literal["up", "down"]
    latency_ms: float | None = None


class Health(_Model):
    status: Literal["ready", "not_ready"]
    api: ApiHealth
    database: DatabaseHealth
