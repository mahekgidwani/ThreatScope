"""The common event model.

`EventIn` is what a client may send. It is strict: unknown or server-owned fields
(id, received_at, risk_score, risk_factors) are rejected, and values are normalised so
the same thing always has the same spelling (UTC times, canonical IPs, punycode domains).
`EventOut` is what the API returns.
"""
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings
from app.enums import Severity, Source
from app.schemas.indicator import IndicatorOut

MAX_DOMAIN_LENGTH = 253
MAX_URL_LENGTH = 1024
ALLOWED_URL_SCHEMES = {"http", "https", "ftp"}
MAX_METADATA_DEPTH = 10  # container levels; real metadata is 2-4 levels deep
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMBER_TEXT = re.compile(r"-?\d+(\.\d+)?")


def _exceeds_depth(value: Any, limit: int) -> bool:
    """True if dicts/lists are nested more than `limit` levels deep.

    Iterative (no recursion) and stops as soon as the limit is passed, so absurdly deep
    or self-referencing data can neither crash nor loop forever.
    """
    stack = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, dict):
            children = item.values()
        elif isinstance(item, (list, tuple)):
            children = item
        else:
            continue
        if level > limit:
            return True
        stack.extend((child, level + 1) for child in children)
    return False


def normalise_domain(value: str) -> str:
    """Return the canonical form of a hostname: lower case, no trailing dot, punycode (xn--).

    Unicode lookalikes such as a Cyrillic 'а' therefore become visibly different from the
    Latin name. Raises ValueError for anything that is not a valid hostname. Also used for
    the `domain` filter of the list API, so filters and stored values always agree.
    """
    name = value[:-1] if value.endswith(".") else value
    if not name:
        raise ValueError("domain must not be empty")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError("domain looks like an IP address; use source_ip or destination_ip instead")
    try:
        ascii_name = name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("domain is not a valid (internationalised) hostname") from None
    if len(ascii_name) > MAX_DOMAIN_LENGTH:
        raise ValueError(f"domain is longer than {MAX_DOMAIN_LENGTH} characters")
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        raise ValueError("domain contains an invalid label or character")
    return ascii_name


def _validate_url(value: str) -> str:
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL is longer than {MAX_URL_LENGTH} characters")
    if not value.isascii():
        raise ValueError("URL must be ASCII; percent-encode any other characters")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("URL must not contain spaces or control characters")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - accessing it validates the port number
    except ValueError:
        raise ValueError("URL is malformed") from None
    if parts.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValueError("URL scheme must be http, https or ftp")
    if not host:
        raise ValueError("URL must include a host")
    return value


class RiskFactor(BaseModel):
    """One line of the risk-score explanation, e.g. {"rule": "severity:high", "points": 40}."""

    rule: str
    points: int


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")
    source: Source
    event_type: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.\-]+$")
    occurred_at: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    severity: Severity
    description: str = Field(min_length=1, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at", mode="before")
    @classmethod
    def _timestamp_must_be_a_date_text(cls, value: Any) -> Any:
        # Numbers (and number-looking text) would be read as Unix time, in seconds or
        # milliseconds depending on size - too ambiguous, so only ISO-8601 text is allowed.
        if not isinstance(value, (str, datetime)) or (
                isinstance(value, str) and _NUMBER_TEXT.fullmatch(value.strip())):
            raise ValueError("occurred_at must be an ISO-8601 timestamp with a timezone")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _timestamp_must_have_a_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone (for example 'Z' or '+05:30')")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _canonical_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:  # Python's own message repeats the input, so replace it
            raise ValueError("not a valid IPv4 or IPv6 address") from None

    @field_validator("domain")
    @classmethod
    def _canonical_domain(cls, value: str | None) -> str | None:
        return None if value is None else normalise_domain(value)

    @field_validator("url")
    @classmethod
    def _safe_url(cls, value: str | None) -> str | None:
        return None if value is None else _validate_url(value)

    @field_validator("file_hash")
    @classmethod
    def _lowercase_hash(cls, value: str | None) -> str | None:
        return None if value is None else value.lower()

    @field_validator("description")
    @classmethod
    def _description_not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("description must not be blank")
        return stripped

    @field_validator("metadata")
    @classmethod
    def _metadata_is_small_plain_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        if _exceeds_depth(value, MAX_METADATA_DEPTH):
            raise ValueError(f"metadata is nested deeper than {MAX_METADATA_DEPTH} levels")
        try:
            size = len(json.dumps(value, ensure_ascii=False, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            raise ValueError("metadata must be plain JSON data (no NaN, no custom objects, "
                             "not absurdly deep)") from None
        limit = get_settings().max_metadata_bytes
        if size > limit:
            raise ValueError(f"metadata is {size} bytes; the limit is {limit}")
        return value


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    external_event_id: str | None = None
    source: Source
    event_type: str
    occurred_at: datetime
    received_at: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    severity: Severity
    risk_score: int
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    description: str
    # The database model calls this attribute `event_metadata`; the API calls it `metadata`.
    metadata: dict[str, Any] = Field(validation_alias=AliasChoices("event_metadata", "metadata"))
    indicators: list[IndicatorOut] = Field(default_factory=list)
