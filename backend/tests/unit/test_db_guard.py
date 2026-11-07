"""The guard that keeps destructive test setup away from the development database."""
import pytest
from sqlalchemy.engine import URL

from app.config import Settings
from tests import db_support
from tests.db_guard import assert_safe_test_database

Failed = pytest.fail.Exception


def url_for(database):
    return URL.create("postgresql+psycopg", username="u", password="pw-fake-123",
                      host="db", port=5432, database=database)


def test_guard_refuses_the_development_database():
    with pytest.raises(Failed):
        assert_safe_test_database(url_for("threatscope"), "threatscope")


def test_guard_refuses_even_when_dev_name_ends_in_test():
    with pytest.raises(Failed):
        assert_safe_test_database(url_for("threatscope_test"), "threatscope_test")


@pytest.mark.parametrize("name", ["prod_db", "threatscope", "test", "", None])
def test_guard_refuses_names_without_test_suffix(name):
    with pytest.raises(Failed):
        assert_safe_test_database(url_for(name), "threatscope")


@pytest.mark.parametrize("name", ['bad"name_test', "x; drop_test", "has space_test", "a-b_test"])
def test_guard_refuses_unsafe_characters(name):
    with pytest.raises(Failed):
        assert_safe_test_database(url_for(name), "threatscope")


def test_guard_accepts_a_proper_test_database():
    assert_safe_test_database(url_for("threatscope_test"), "threatscope")  # must not raise


def test_postgres_builder_runs_the_guard_before_creating_any_engine(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("an engine was created before the guard ran")

    monkeypatch.setattr(db_support, "create_engine", forbidden)
    unsafe = Settings(_env_file=None, ingest_api_key="Zx9-test-key-0123456789abcdef",
                      postgres_user="u", postgres_password="pw-fake-123", postgres_db='bad"name')
    with pytest.raises(Failed):
        db_support.build_postgres_engine(unsafe)
