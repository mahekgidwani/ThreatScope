"""Paging limits shared by every list endpoint."""
from app.errors import InvalidFilterError

DEFAULT_LIMIT = 50
MAX_LIMIT = 100


def check_paging(limit: int, offset: int) -> None:
    if not 1 <= limit <= MAX_LIMIT:
        raise InvalidFilterError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise InvalidFilterError("offset must be 0 or greater")
