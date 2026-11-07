"""Safety guard: destructive test setup may only ever touch a dedicated test database."""
import re

import pytest
from sqlalchemy.engine import URL

# Letters, digits and underscores only, ending in _test. Rejecting every other character
# also means the name can be placed safely inside a quoted CREATE DATABASE statement.
_SAFE_NAME = re.compile(r"[A-Za-z0-9_]+_test")


def assert_safe_test_database(url: URL, dev_db_name: str) -> None:
    """Fail the test run unless `url` points at a database that is clearly a test database."""
    name = url.database or ""
    if name == dev_db_name or not _SAFE_NAME.fullmatch(name):
        pytest.fail(
            f"Refusing destructive test setup on database {name!r}: the name must match "
            f"[A-Za-z0-9_]+_test and differ from the development database {dev_db_name!r}.",
            pytrace=False,
        )
