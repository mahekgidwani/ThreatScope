"""Response schemas: EventOut / IndicatorOut / IncidentOut / Page / HealthOut / errors."""
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.enums import IncidentStatus, IndicatorType, Severity, Source
from app.models import Event, Incident, Indicator
from app.schemas.common import ErrorBody, ErrorResponse, Page
from app.schemas.event import EventOut, RiskFactor
from app.schemas.health import ApiHealth, DatabaseHealth, HealthOut
from app.schemas.incident import IncidentOut
from app.schemas.indicator import IndicatorOut

NOW = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)


def orm_event(**over) -> Event:
    values = dict(id=uuid.uuid4(), source="honeypot", event_type="xss_attempt", occurred_at=NOW,
                  received_at=NOW, severity="high", risk_score=55, description="d",
                  risk_factors=[{"rule": "severity:high", "points": 40}, {"rule": "source:honeypot", "points": 15}],
                  event_metadata={"rule": "9500001"}, source_ip="203.0.113.42")
    return Event(**{**values, **over})


def test_event_out_reads_an_orm_event_and_exposes_metadata_under_its_api_name():
    ev = orm_event()
    out = EventOut.model_validate(ev)
    assert out.id == ev.id
    assert (out.source, out.severity) == (Source.honeypot, Severity.high)
    assert out.metadata == {"rule": "9500001"}
    assert out.risk_factors == [RiskFactor(rule="severity:high", points=40),
                                RiskFactor(rule="source:honeypot", points=15)]
    assert out.indicators == []
    dumped = json.loads(out.model_dump_json(by_alias=True))
    assert dumped["metadata"] == {"rule": "9500001"}
    assert "event_metadata" not in dumped
    assert dumped["occurred_at"].endswith("Z")


def test_event_out_includes_linked_indicators():
    ev = orm_event()
    ev.indicators.append(Indicator(id=1, type="ip", value="203.0.113.42", first_seen=NOW,
                                   last_seen=NOW, sighting_count=1))
    out = EventOut.model_validate(ev)
    assert [(i.type, i.value, i.sighting_count) for i in out.indicators] == [
        (IndicatorType.ip, "203.0.113.42", 1)]


def test_event_out_also_accepts_a_plain_dict_with_metadata_key():
    data = EventOut.model_validate(orm_event()).model_dump(by_alias=True)
    assert EventOut.model_validate(data).metadata == {"rule": "9500001"}


def test_indicator_out_from_orm():
    out = IndicatorOut.model_validate(Indicator(id=7, type="domain", value="evil.example",
                                                first_seen=NOW, last_seen=NOW, sighting_count=3))
    assert (out.id, out.type, out.value, out.sighting_count) == (7, IndicatorType.domain, "evil.example", 3)


def test_incident_out_from_orm():
    out = IncidentOut.model_validate(Incident(id=1, title="t", status="open", severity="high",
                                              risk_score=0, created_at=NOW, updated_at=NOW, summary=None))
    assert (out.status, out.severity, out.summary) == (IncidentStatus.open, Severity.high, None)


def test_page_wraps_items_with_paging_numbers():
    page = Page[IndicatorOut](items=[], total=0, limit=50, offset=0)
    assert page.model_dump() == {"items": [], "total": 0, "limit": 50, "offset": 0}
    with pytest.raises(ValidationError):
        Page[IndicatorOut](items=[{"bogus": 1}], total=1, limit=50, offset=0)


def test_error_response_has_the_documented_shape():
    body = ErrorResponse(error=ErrorBody(code="not_found", message="Event not found"))
    assert body.model_dump() == {"error": {"code": "not_found", "message": "Event not found", "details": {}}}


def test_health_shape_ready_and_degraded():
    ready = HealthOut(status="ready", api=ApiHealth(), database=DatabaseHealth(status="up", latency_ms=1.2))
    assert ready.model_dump() == {"status": "ready", "api": {"status": "up"},
                                  "database": {"status": "up", "latency_ms": 1.2}}
    down = HealthOut(status="not_ready", api=ApiHealth(), database=DatabaseHealth(status="down"))
    assert down.model_dump()["database"] == {"status": "down", "latency_ms": None}
    with pytest.raises(ValidationError):
        HealthOut(status="maybe", api=ApiHealth(), database=DatabaseHealth(status="up"))
