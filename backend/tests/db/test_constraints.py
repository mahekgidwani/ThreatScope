"""Constraint, relationship and schema tests. Every test taking `engine` or `session`
runs twice: on in-memory SQLite and on real PostgreSQL."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.db import Base
from app.enums import Severity, Source
from app.models import Event, EventIndicator, Incident, IncidentEvent, Indicator

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))


def make_event(**over) -> Event:
    values = dict(source="honeypot", event_type="xss_attempt",
                  occurred_at=datetime(2026, 11, 7, 10, 0, tzinfo=UTC),
                  severity="high", description="test event", risk_score=0)
    return Event(**{**values, **over})


def make_indicator(**over) -> Indicator:
    return Indicator(**{**dict(type="ip", value="203.0.113.1"), **over})


def make_incident(**over) -> Incident:
    return Incident(**{**dict(title="test incident", severity="high"), **over})


def count(session: Session, model) -> int:
    return session.scalar(select(func.count()).select_from(model))


# ---- events ----------------------------------------------------------------------

def test_event_roundtrip_keeps_utc_and_sets_defaults(session):
    original = datetime(2026, 11, 7, 15, 30, tzinfo=IST)
    session.add(make_event(occurred_at=original, source=Source.honeypot, severity=Severity.high))
    session.commit()
    session.expunge_all()

    loaded = session.scalars(select(Event)).one()
    assert isinstance(loaded.id, uuid.UUID)
    assert loaded.occurred_at.utcoffset() == timedelta(0)
    assert loaded.occurred_at == original                    # same instant
    assert loaded.received_at.utcoffset() == timedelta(0)    # server timestamp, aware
    assert loaded.event_metadata == {}
    assert loaded.risk_factors == []
    assert (loaded.source, loaded.severity) == ("honeypot", "high")


def test_naive_datetime_is_rejected(session):
    session.add(make_event(occurred_at=datetime(2026, 11, 7, 10, 0)))
    with pytest.raises((StatementError, ValueError)):
        session.flush()


def test_unique_external_id_per_source(session):
    session.add(make_event(external_event_id="ext-1"))
    session.commit()

    session.add(make_event(external_event_id="ext-1"))           # same source + same id
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()

    session.add(make_event(external_event_id="ext-1", source="domain"))   # other source: fine
    session.add(make_event(external_event_id=None))                        # no external id: fine
    session.add(make_event(external_event_id=None))                        # twice: fine
    session.commit()
    assert count(session, Event) == 4


@pytest.mark.parametrize("bad", [
    dict(severity="bogus"), dict(source="bogus"), dict(risk_score=101), dict(risk_score=-1),
], ids=["severity", "source", "risk_over_100", "risk_negative"])
def test_event_check_constraints(session, bad):
    session.add(make_event(**bad))
    with pytest.raises(IntegrityError):
        session.flush()


def test_event_risk_score_boundaries_are_allowed(session):
    session.add_all([make_event(risk_score=0), make_event(risk_score=100)])
    session.commit()
    assert count(session, Event) == 2


# ---- indicators ------------------------------------------------------------------

def test_indicator_unique_type_and_value(session):
    session.add(make_indicator())
    session.commit()
    session.add(make_indicator())
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()
    session.add(make_indicator(type="domain"))     # same value, other type: fine
    session.commit()
    assert count(session, Indicator) == 2


def test_indicator_defaults_and_checks(session):
    ind = make_indicator()
    session.add(ind)
    session.commit()
    assert ind.sighting_count == 1
    assert ind.first_seen.utcoffset() == timedelta(0)
    assert ind.last_seen.utcoffset() == timedelta(0)


@pytest.mark.parametrize("bad", [dict(sighting_count=0), dict(type="bogus")])
def test_indicator_check_constraints(session, bad):
    session.add(make_indicator(**bad))
    with pytest.raises(IntegrityError):
        session.flush()


# ---- incidents -------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    dict(status="bogus"), dict(severity="bogus"), dict(risk_score=101), dict(risk_score=-1),
])
def test_incident_check_constraints(session, bad):
    session.add(make_incident(**bad))
    with pytest.raises(IntegrityError):
        session.flush()


def test_incident_defaults(session):
    inc = make_incident()
    session.add(inc)
    session.commit()
    assert (inc.status, inc.risk_score) == ("open", 0)
    assert inc.created_at.utcoffset() == timedelta(0)
    assert inc.updated_at.utcoffset() == timedelta(0)


# ---- link tables -----------------------------------------------------------------

def test_duplicate_event_indicator_link_is_rejected(session):
    ev, ind = make_event(), make_indicator()
    session.add_all([ev, ind])
    session.commit()
    session.add(EventIndicator(event_id=ev.id, indicator_id=ind.id))
    session.commit()
    session.add(EventIndicator(event_id=ev.id, indicator_id=ind.id))
    with pytest.raises(IntegrityError):
        session.flush()


def test_duplicate_incident_event_link_is_rejected(session):
    ev, inc = make_event(), make_incident()
    session.add_all([ev, inc])
    session.commit()
    session.add(IncidentEvent(incident_id=inc.id, event_id=ev.id))
    session.commit()
    session.add(IncidentEvent(incident_id=inc.id, event_id=ev.id))
    with pytest.raises(IntegrityError):
        session.flush()


def test_links_must_point_at_real_rows(session):
    session.add(EventIndicator(event_id=uuid.uuid4(), indicator_id=999))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()
    session.add(IncidentEvent(incident_id=999, event_id=uuid.uuid4()))
    with pytest.raises(IntegrityError):
        session.flush()


def test_relationship_navigation(session):
    a, b = make_indicator(value="203.0.113.1"), make_indicator(type="domain", value="evil.example")
    ev = make_event()
    ev.indicators.extend([a, b])
    inc = make_incident()
    inc.events.append(ev)
    session.add_all([ev, inc])
    session.commit()
    session.expunge_all()

    loaded = session.scalars(select(Event)).one()
    assert {i.value for i in loaded.indicators} == {"203.0.113.1", "evil.example"}
    assert [e.id for e in loaded.indicators[0].events] == [loaded.id]
    assert session.scalars(select(Incident)).one().events[0].id == loaded.id
    assert count(session, EventIndicator) == 2


def test_database_cascades_when_an_event_is_deleted(session):
    ev, ind, inc = make_event(), make_indicator(), make_incident()
    ev.indicators.append(ind)
    inc.events.append(ev)
    session.add_all([ev, ind, inc])
    session.commit()

    # A bulk delete bypasses the ORM, so only the database's ON DELETE CASCADE can clean up.
    session.execute(delete(Event))
    session.commit()
    assert count(session, EventIndicator) == 0
    assert count(session, IncidentEvent) == 0
    assert count(session, Indicator) == 1      # indicator survives
    assert count(session, Incident) == 1       # incident survives


def test_database_cascades_when_an_indicator_or_incident_is_deleted(session):
    ev, ind, inc = make_event(), make_indicator(), make_incident()
    ev.indicators.append(ind)
    inc.events.append(ev)
    session.add_all([ev, ind, inc])
    session.commit()

    session.execute(delete(Indicator))
    session.execute(delete(Incident))
    session.commit()
    assert count(session, EventIndicator) == 0
    assert count(session, IncidentEvent) == 0
    assert count(session, Event) == 1


# ---- schema shape ----------------------------------------------------------------

def test_exactly_the_five_phase2_tables_exist(engine):
    assert set(inspect(engine).get_table_names()) == {
        "events", "indicators", "event_indicators", "incidents", "incident_events"}


def test_database_has_the_expected_named_constraints_and_indexes(engine):
    insp = inspect(engine)
    assert "uq_events_source_external_event_id" in {u["name"] for u in insp.get_unique_constraints("events")}
    assert "uq_indicators_type_value" in {u["name"] for u in insp.get_unique_constraints("indicators")}
    assert {"ix_events_occurred_at", "ix_events_source_event_type", "ix_events_severity",
            "ix_events_source_ip", "ix_events_domain"} <= {i["name"] for i in insp.get_indexes("events")}
    assert "ix_event_indicators_indicator_id" in {i["name"] for i in insp.get_indexes("event_indicators")}
    assert "ix_incident_events_event_id" in {i["name"] for i in insp.get_indexes("incident_events")}
    assert "ix_incidents_status" in {i["name"] for i in insp.get_indexes("incidents")}


def test_constraint_names_follow_the_naming_convention():
    """Stable, predictable names are what make a later Alembic migration painless."""
    def names(table, kind):
        return {c.name for c in Base.metadata.tables[table].constraints if c.__class__.__name__ == kind}

    assert "uq_events_source_external_event_id" in names("events", "UniqueConstraint")
    assert "pk_events" in names("events", "PrimaryKeyConstraint")
    assert {"ck_events_source_valid", "ck_events_severity_valid", "ck_events_risk_score_range"} \
        <= names("events", "CheckConstraint")
    assert "pk_event_indicators" in names("event_indicators", "PrimaryKeyConstraint")
    assert "fk_event_indicators_event_id_events" in names("event_indicators", "ForeignKeyConstraint")
    assert "pk_incident_events" in names("incident_events", "PrimaryKeyConstraint")


@pytest.mark.postgres
def test_postgres_stores_metadata_as_jsonb_and_roundtrips_it(pg_engine):
    payload = {"rule": "9500001", "tags": ["xss", "owasp"], "nested": {"ünïcode": "値", "n": 1.5, "ok": True}}
    with Session(pg_engine) as s:
        s.add(make_event(event_metadata=payload, risk_factors=[{"rule": "severity:high", "points": 40}]))
        s.commit()
    with Session(pg_engine) as s:
        loaded = s.scalars(select(Event)).one()
        assert loaded.event_metadata == payload
        assert loaded.risk_factors == [{"rule": "severity:high", "points": 40}]
    columns = {c["name"]: c for c in inspect(pg_engine).get_columns("events")}
    assert type(columns["metadata"]["type"]).__name__ == "JSONB"
    assert type(columns["occurred_at"]["type"]).__name__ == "TIMESTAMP"
    assert columns["occurred_at"]["type"].timezone is True
