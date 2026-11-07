"""Building blocks shared by several responses."""
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """A page of results: `total` counts all matches, `limit`/`offset` echo the request."""

    items: list[T]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Every error the API returns has exactly this shape."""

    error: ErrorBody
