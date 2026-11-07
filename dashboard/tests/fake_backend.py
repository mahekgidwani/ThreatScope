"""An in-memory stand-in for the ThreatScope API, speaking its real query rules (filters, newest-first order,
limit <= 100, {"error": ...} bodies). Used as an httpx MockTransport handler, so the real client code runs."""
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

HEALTH_READY = {"status": "ready", "api": {"status": "up"}, "database": {"status": "up", "latency_ms": 3.8}}
HEALTH_DOWN = {"status": "not_ready", "api": {"status": "up"}, "database": {"status": "down", "latency_ms": None}}
T0 = datetime(2026, 11, 7, 4, 0, tzinfo=timezone.utc)


def _z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def indicator(id: int = 1, type: str = "ip", value: str = "203.0.113.42", sightings: int = 1, last: datetime = T0) -> dict:
    return {"id": id, "type": type, "value": value, "first_seen": _z(T0), "last_seen": _z(last), "sighting_count": sightings}


def event(n: int = 1, *, source: str = "honeypot", severity: str = "high", at: datetime | None = None, risk: int = 60,
          event_type: str = "xss_attempt", description: str = "Demo event", source_ip: str | None = None,
          domain: str | None = None, url: str | None = None, file_hash: str | None = None,
          metadata: dict[str, Any] | None = None, indicators: list[dict] | None = None) -> dict:
    at = at or T0 + timedelta(minutes=n)
    return {"id": f"00000000-0000-4000-8000-{n:012d}", "external_event_id": f"ext-{n}", "source": source,
            "event_type": event_type, "occurred_at": _z(at), "received_at": _z(at + timedelta(seconds=5)),
            "source_ip": source_ip, "destination_ip": None, "domain": domain, "url": url, "file_hash": file_hash,
            "severity": severity, "risk_score": risk, "risk_factors": [{"rule": f"severity:{severity}", "points": 40}],
            "description": description, "metadata": metadata or {}, "indicators": indicators or []}


def incident(id: int = 1, status: str = "open", severity: str = "high") -> dict:
    return {"id": id, "title": f"Incident {id}", "status": status, "severity": severity, "risk_score": 70,
            "created_at": _z(T0), "updated_at": _z(T0), "summary": None}


class FakeBackend:
    def __init__(self, events=(), indicators=(), incidents=(), health=HEALTH_READY, health_status=200, down=False):
        self.events, self.indicators, self.incidents = list(events), list(indicators), list(incidents)
        self.health, self.health_status, self.down = health, health_status, down
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("connection refused")
        path, q = request.url.path, dict(request.url.params)
        if path == "/health":
            return httpx.Response(self.health_status, json=self.health)
        if path == "/api/v1/events":
            return self._page(self._filter_events(q), q)
        if path.startswith("/api/v1/events/"):
            found = [e for e in self.events if e["id"] == path.rsplit("/", 1)[1]]
            return httpx.Response(200, json=found[0]) if found else self._error(404, "not_found", "Event not found")
        if path == "/api/v1/indicators":
            rows = [i for i in self.indicators if q.get("type") in (None, i["type"]) and q.get("value") in (None, i["value"])]
            return self._page(sorted(rows, key=lambda i: (i["last_seen"], i["id"]), reverse=True), q)
        if path == "/api/v1/incidents":
            rows = [i for i in self.incidents if q.get("status") in (None, i["status"])]
            return self._page(sorted(rows, key=lambda i: (i["created_at"], i["id"]), reverse=True), q)
        return self._error(404, "not_found", "Not found")

    def _filter_events(self, q: dict) -> list[dict]:
        rows = self.events
        for key in ("source", "event_type", "severity", "source_ip", "domain"):
            if key in q:
                rows = [e for e in rows if e[key] == q[key]]
        if "start_time" in q:
            rows = [e for e in rows if _parse(e["occurred_at"]) >= _parse(q["start_time"])]
        if "end_time" in q:
            rows = [e for e in rows if _parse(e["occurred_at"]) < _parse(q["end_time"])]
        return sorted(rows, key=lambda e: (e["occurred_at"], e["id"]), reverse=True)

    def _page(self, rows: list[dict], q: dict) -> httpx.Response:
        limit, offset = int(q.get("limit", 50)), int(q.get("offset", 0))
        if not 1 <= limit <= 100 or offset < 0:
            return self._error(422, "validation_error", "Request validation failed")
        return httpx.Response(200, json={"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset})

    @staticmethod
    def _error(status: int, code: str, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": message, "details": {}}})


def _parse(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))
