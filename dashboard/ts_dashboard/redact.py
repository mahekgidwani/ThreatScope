"""Hide secrets before event metadata is shown or exported.

Events come from outside (log lines, files), so their metadata can hold credentials. Values under
sensitive-looking keys are replaced, and credentials inside URLs are masked.
shortcut: key-name and URL-credential matching only, add value-pattern scanning if a source starts putting tokens in free text.
"""
import re
from typing import Any

REDACTED = "[redacted]"
MAX_DEPTH = 10
_SENSITIVE_KEY = re.compile(
    r"pass(word|wd|phrase)?|secret|token|api[_-]?key|authorization|auth|cookie|session|credential|private[_-]?key",
    re.IGNORECASE)
_URL_CREDENTIALS = re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)


def redact(value: Any, _depth: int = 0) -> Any:
    """A copy of `value` (nested dicts / lists / strings) that is safe to display."""
    if _depth > MAX_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        return {key: REDACTED if _SENSITIVE_KEY.search(str(key)) else redact(item, _depth + 1)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return _URL_CREDENTIALS.sub(r"\g<scheme>" + REDACTED + "@", value)
    return value
