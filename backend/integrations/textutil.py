"""Text helpers shared by the adapters."""


def clean(text: str, limit: int) -> str:
    """Text safe for JSON, descriptions and terminals: valid UTF-8, control characters replaced
    by '?', surrounding blanks removed, at most `limit` characters. May be empty."""
    text = text.encode("utf-8", "replace").decode("utf-8")
    return "".join(ch if ch.isprintable() else "?" for ch in text).strip()[:limit]
