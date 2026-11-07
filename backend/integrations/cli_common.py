"""Small pieces every adapter command line shares."""
import sys

from pydantic import ValidationError

from app.logging_config import configure_logging
from integrations.client import ThreatScopeClient
from integrations.config import load_settings


def connect(settings_loader=load_settings) -> ThreatScopeClient | None:
    """A client built from the environment, or None (after printing why) if the configuration is
    unusable. Logging is set up with the API key registered for redaction."""
    try:
        settings = settings_loader()
    except ValidationError as exc:
        fields = ", ".join(sorted({str(err["loc"][0]).upper() for err in exc.errors() if err["loc"]}))
        print(f"configuration error: check {fields} (see .env.example)", file=sys.stderr)
        return None
    configure_logging("WARNING", secrets=[settings.ingest_api_key.get_secret_value()])
    return ThreatScopeClient(settings)
