"""An in-memory stand-in for the ThreatScope API, speaking its real query rules (filters, newest-first order,
limit <= 100, {"error": ...} bodies). Used as an httpx MockTransport handler, so the real client code runs."""
from datetime import datetime, timedelta, timezone
from typing import Any

import json

import httpx

TEST_KEY = "test-key-0123456789abcdef"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
HEALTH_READY = {"status": "ready", "api": {"status": "up"}, "database": {"status": "up", "latency_ms": 3.8}}
HEALTH_DOWN = {"status": "not_ready", "api": {"status": "up"}, "database": {"status": "down", "latency_ms": None}}
T0 = datetime(2026, 11, 7, 4, 0, tzinfo=timezone.utc)


def tick_clock(monkeypatch, *view_modules) -> None:
    """Make `datetime.now()` in the given view modules start at 12:01:30 UTC on T0's day and advance one second per
    call, like a real clock between Streamlit reruns. 12:01:30 is more than a minute from any 5-minute boundary."""
    calls = iter(range(10_000))

    class TickingDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 7, 12, 1, 30, tzinfo=timezone.utc) + timedelta(seconds=next(calls), microseconds=123)

    for module in view_modules:
        monkeypatch.setattr(module, "datetime", TickingDatetime)


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


def incident(id: int = 1, status: str = "open", severity: str = "high", event_ids: tuple = (), title: str | None = None,
             summary: str | None = None) -> dict:
    """`event_ids` is test-side bookkeeping: the fake backend uses it to answer detail requests and strips it from lists."""
    return {"id": id, "title": title or f"Incident {id}", "status": status, "severity": severity, "risk_score": 70,
            "created_at": _z(T0), "updated_at": _z(T0), "summary": summary, "event_ids": list(event_ids)}


class FakeBackend:
    def __init__(self, events=(), indicators=(), incidents=(), health=HEALTH_READY, health_status=200, down=False,
                 api_key: str = TEST_KEY):
        self.events, self.indicators, self.incidents = list(events), list(indicators), list(incidents)
        self.api_key = api_key
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
            if q.get("type") == "ip" and q.get("value", "").count(".") != 3:      # the real API validates ip/domain filters
                return self._error(422, "invalid_filter", "value is not a valid IP address")
            rows = [i for i in self.indicators if q.get("type") in (None, i["type"]) and q.get("value") in (None, i["value"])]
            return self._page(sorted(rows, key=lambda i: (i["last_seen"], i["id"]), reverse=True), q)
        if path == "/api/v1/incidents" and request.method == "GET":
            rows = [i for i in self.incidents if q.get("status") in (None, i["status"])]
            return self._page([self._summary(i) for i in sorted(rows, key=lambda i: (i["created_at"], i["id"]), reverse=True)], q)
        if path == "/api/v1/incidents" and request.method == "POST":
            return self._create_incident(request)
        if path.startswith("/api/v1/incidents/"):
            found = [i for i in self.incidents if str(i["id"]) == path.rsplit("/", 1)[1]]
            if not found:
                return self._error(404, "not_found", "Incident not found")
            return self._patch_incident(request, found[0]) if request.method == "PATCH" else httpx.Response(200, json=self._detail(found[0]))
        return self._error(404, "not_found", "Not found")

    # -- incidents ------------------------------------------------------------------------------

    @staticmethod
    def _summary(incident: dict) -> dict:
        return {**{k: v for k, v in incident.items() if k != "event_ids"}, "event_count": len(incident["event_ids"])}

    def _detail(self, incident: dict) -> dict:
        members = sorted((e for e in self.events if e["id"] in incident["event_ids"]), key=lambda e: (e["occurred_at"], e["id"]), reverse=True)
        return {**self._summary(incident), "events": members}

    def _unauthorised(self, request: httpx.Request) -> httpx.Response | None:
        if request.headers.get("x-api-key") != self.api_key:
            return self._error(401, "unauthorized", "Missing or invalid API key")
        return None

    def _bad(self, field: str, msg: str) -> httpx.Response:
        return httpx.Response(422, json={"error": {"code": "validation_error", "message": "Request validation failed",
                                                   "details": [{"loc": ["body", field], "type": "value_error", "msg": msg}]}})

    def _roll_up(self, incident: dict) -> None:
        members = [e for e in self.events if e["id"] in incident["event_ids"]]
        incident["severity"] = max((e["severity"] for e in members), key=SEVERITY_ORDER.index)
        incident["risk_score"] = max(e["risk_score"] for e in members)

    def _create_incident(self, request: httpx.Request) -> httpx.Response:
        if (denied := self._unauthorised(request)):
            return denied
        body = json.loads(request.content)
        title = (body.get("title") or "").strip()
        ids = list(dict.fromkeys(body.get("event_ids") or []))
        if not title:
            return self._bad("title", "title must not be blank")
        if len(title) > 200:
            return self._bad("title", "title must be at most 200 characters")
        if not ids:
            return self._bad("event_ids", "List should have at least 1 item")
        if any(i not in {e["id"] for e in self.events} for i in ids):
            return self._error(404, "not_found", "Event not found")
        new = incident(max([i["id"] for i in self.incidents], default=0) + 1, event_ids=tuple(ids), title=title, summary=body.get("summary"))
        self._roll_up(new)
        self.incidents.append(new)
        return httpx.Response(201, json=self._detail(new))

    def _patch_incident(self, request: httpx.Request, incident_row: dict) -> httpx.Response:
        if (denied := self._unauthorised(request)):
            return denied
        body = json.loads(request.content)
        if body.get("status") is not None and body["status"] not in ("open", "investigating", "closed"):
            return self._bad("status", "Input should be 'open', 'investigating' or 'closed'")
        ids = list(incident_row["event_ids"])
        known = {e["id"] for e in self.events}
        if any(i not in known for i in body.get("add_event_ids", [])):
            return self._error(404, "not_found", "Event not found")
        ids = [i for i in dict.fromkeys(ids + body.get("add_event_ids", [])) if i not in body.get("remove_event_ids", [])]
        if not ids:
            return self._error(422, "invalid_filter", "an incident must keep at least one event")
        incident_row["event_ids"] = ids
        for key in ("status", "title"):
            if body.get(key) is not None:
                incident_row[key] = body[key]
        if "summary" in body:
            incident_row["summary"] = body["summary"] or None
        self._roll_up(incident_row)
        return httpx.Response(200, json=self._detail(incident_row))

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
