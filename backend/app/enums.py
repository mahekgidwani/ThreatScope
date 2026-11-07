"""Fixed vocabularies shared by the database models and the API schemas.

They are stored in the database as plain text; CHECK constraints keep the text valid.
"""
from enum import StrEnum


class Source(StrEnum):
    domain = "domain"
    honeypot = "honeypot"
    file = "file"
    network = "network"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IndicatorType(StrEnum):
    ip = "ip"
    domain = "domain"
    url = "url"
    sha256 = "sha256"


class IncidentStatus(StrEnum):
    open = "open"
    investigating = "investigating"
    closed = "closed"
