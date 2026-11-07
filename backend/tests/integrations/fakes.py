"""A ThreatScopeClient wired to a Python function instead of a network (for CLI/adapter tests)."""
import httpx

from integrations.client import ThreatScopeClient
from integrations.config import IntegrationSettings

KEY = "k3y-for-tests-0123456789abcdef"


def fake_client(handler) -> ThreatScopeClient:
    http = httpx.Client(base_url="http://testserver", transport=httpx.MockTransport(handler))
    return ThreatScopeClient(IntegrationSettings(_env_file=None, ingest_api_key=KEY), http_client=http)


def created(request):
    return httpx.Response(201, json={"id": "11111111-1111-1111-1111-111111111111"})


def duplicate(request):
    return httpx.Response(409, json={"error": {"code": "duplicate_event", "message": "m",
                                               "details": {"existing_id": "abc-1"}}})


def error_reply(status, code, message="m"):
    return httpx.Response(status, json={"error": {"code": code, "message": message, "details": {}}})
