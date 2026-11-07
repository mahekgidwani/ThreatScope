"""Tests for app.logging_config. Only fake secrets are used."""
import logging
import re

import pytest

from app.logging_config import HANDLER_ATTR, configure_logging


@pytest.fixture(autouse=True)
def restore_logging():
    """Put the global logging state back after every test."""
    root = logging.getLogger()
    engine = logging.getLogger("sqlalchemy.engine")
    saved = (root.handlers[:], root.level, engine.level)
    yield
    root.handlers[:] = saved[0]
    root.setLevel(saved[1])
    engine.setLevel(saved[2])


def our_handlers():
    return [h for h in logging.getLogger().handlers if getattr(h, HANDLER_ATTR, False)]


def test_line_has_time_level_logger_name_and_message(capsys):
    configure_logging("INFO")
    logging.getLogger("threatscope.test").info("hello %s", "world")
    line = capsys.readouterr().err.strip()
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} INFO threatscope\.test hello world", line)


def test_level_is_respected(capsys):
    configure_logging("WARNING")
    log = logging.getLogger("threatscope.test")
    log.info("quiet-info")
    log.warning("loud-warning")
    err = capsys.readouterr().err
    assert "quiet-info" not in err
    assert "loud-warning" in err


@pytest.mark.parametrize("bad", ["LOUD", "", "42", None])
def test_invalid_level_falls_back_to_info(bad):
    configure_logging(bad)
    assert logging.getLogger().level == logging.INFO


def test_lowercase_level_is_accepted():
    configure_logging("debug")
    assert logging.getLogger().level == logging.DEBUG


def test_secrets_are_redacted_in_message_and_arguments(capsys):
    configure_logging("INFO", secrets=["pw-FAKE-123", "Zx9-fake-api-key"])
    log = logging.getLogger("threatscope.test")
    log.info("login with pw-FAKE-123")
    log.info("header=%s", "Zx9-fake-api-key")
    err = capsys.readouterr().err
    assert "pw-FAKE-123" not in err
    assert "Zx9-fake-api-key" not in err
    assert err.count("***") == 2


def test_secrets_are_redacted_in_tracebacks(capsys):
    configure_logging("INFO", secrets=["pw-FAKE-123"])
    try:
        raise ValueError("connect failed for pw-FAKE-123")
    except ValueError:
        logging.getLogger("threatscope.test").exception("failed")
    err = capsys.readouterr().err
    assert "Traceback" in err and "ValueError" in err
    assert "pw-FAKE-123" not in err


def test_empty_and_very_short_secrets_are_ignored(capsys):
    configure_logging("INFO", secrets=["", "ab", None])
    logging.getLogger("threatscope.test").info("abc ab plain")
    assert "abc ab plain" in capsys.readouterr().err


def test_reconfiguring_keeps_exactly_one_of_our_handlers(capsys):
    configure_logging("INFO")
    configure_logging("INFO")
    logging.getLogger("threatscope.test").info("once")
    assert len(our_handlers()) == 1
    assert capsys.readouterr().err.count("once") == 1


def test_foreign_handlers_are_left_alone():
    foreign = logging.NullHandler()
    logging.getLogger().addHandler(foreign)
    configure_logging("INFO")
    assert foreign in logging.getLogger().handlers


def test_sqlalchemy_engine_logger_stays_quiet_even_at_debug():
    configure_logging("DEBUG")
    assert logging.getLogger("sqlalchemy.engine").getEffectiveLevel() >= logging.WARNING
