"""Paging limits and input checks shared by every list endpoint."""
from app.errors import InvalidFilterError

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
MAX_OFFSET = 2**63 - 1  # the largest value the database's bigint can hold; more would be a database error


def check_paging(limit: int, offset: int) -> None:
    if not 1 <= limit <= MAX_LIMIT:
        raise InvalidFilterError(f"limit must be between 1 and {MAX_LIMIT}")
    if not 0 <= offset <= MAX_OFFSET:
        raise InvalidFilterError(f"offset must be between 0 and {MAX_OFFSET}")


def check_text_filter(name: str, value: str) -> str:
    """Exact-match text filters: PostgreSQL cannot compare against (or store) a NUL character."""
    if "\x00" in value:
        raise InvalidFilterError(f"{name} must not contain NUL characters")
    return value
