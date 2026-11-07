"""Standard-library logging setup. No extra dependencies.

Every log line looks like:  2026-11-07 10:00:00,123 INFO app.module message
Known secret values (API key, DB password) can be passed in; any occurrence in a
message, its arguments or a traceback is replaced with '***' before it is written.
"""
import logging
from collections.abc import Iterable

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
HANDLER_ATTR = "_threatscope_handler"  # marks the one handler this module owns
REDACTION = "***"
MIN_SECRET_LENGTH = 4  # shorter strings would mangle ordinary log text

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class RedactingFormatter(logging.Formatter):
    """Formats a record normally, then masks known secrets in the final text."""

    def __init__(self, secrets: Iterable[str | None] = ()):
        super().__init__(LOG_FORMAT)
        usable = {s for s in secrets if isinstance(s, str) and len(s) >= MIN_SECRET_LENGTH}
        self._secrets = sorted(usable, key=len, reverse=True)  # longest first

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)  # message + args + traceback, all in one string
        for secret in self._secrets:
            text = text.replace(secret, REDACTION)
        return text


def configure_logging(level: str | None = "INFO", secrets: Iterable[str | None] = ()) -> None:
    """Send all logs to stderr at `level`. Safe to call more than once.

    An unknown level falls back to INFO. Handlers added by other code (pytest, uvicorn)
    are left alone; only the handler created here is replaced on a second call.
    """
    numeric_level = _LEVELS.get(str(level).strip().upper(), logging.INFO)

    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, HANDLER_ATTR, False):
            root.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler()  # stderr
    handler.setFormatter(RedactingFormatter(secrets))
    setattr(handler, HANDLER_ATTR, True)
    root.addHandler(handler)
    root.setLevel(numeric_level)

    # SQL statements and their parameters can contain sensitive data: keep them out of logs.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
