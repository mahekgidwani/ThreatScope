# ThreatScope Phase 4: dashboard

Streamlit dashboard that reads real data from the FastAPI backend. Task 1 (foundation) is done; pages arrive in Tasks 2-7.

```
Dashboard (Streamlit, Windows host) -> ts_dashboard.api_client -> FastAPI (:8000) -> services -> PostgreSQL
```

## Layout

```
dashboard/
  app.py                 entry point (Task 1: shows /health only)
  .streamlit/config.toml bound to 127.0.0.1:8501, no telemetry, dark base theme
  requirements*.txt      streamlit, httpx, pydantic, pydantic-settings (+ pytest for dev)
  ts_dashboard/
    config.py            THREATSCOPE_API_URL, THREATSCOPE_TIMEOUT_SECONDS (no key)
    api_client.py        read-only client + ApiError family with user_message
    models.py            validated copies of the API's JSON (no backend imports)
    redact.py            hides secrets in metadata before display/export
  tests/                 65 tests, no browser, no database, mocked HTTP
```

## Run

```powershell
Set-Location F:\ThreaScope\dashboard
streamlit run app.py            # http://127.0.0.1:8501 ; the backend must be up: docker compose up -d
```

Tests run in the existing backend image (Python 3.12, no new image or install):

```powershell
Set-Location F:\ThreaScope
docker compose run --rm --no-deps -v "${PWD}\dashboard:/dash" -w /dash backend pytest -q -p no:cacheprovider
```

## Rules

1. HTTP only. The dashboard imports no backend code, no SQLAlchemy, no database driver (`tests/test_architecture.py`).
2. **No API key in the dashboard.** All endpoints it uses are `GET` and open; only `POST /api/v1/events` needs `X-API-Key`.
   The dashboard never writes, so it is not given the key. If Task 5 needs writes (incident status), that decision is made then.
3. No caching in the client: what a page shows was just read from the API. When the API fails the page shows the error, not old data.
4. Risk scores are shown as the backend computed them, labelled "Experimental prioritisation score - not a probability of compromise."

## Endpoints used

| Endpoint | Parameters |
|---|---|
| `GET /health` | 200 ready, 503 database down (both have a body) |
| `GET /api/v1/events` | `source`, `event_type`, `severity`, `source_ip`, `domain`, `start_time`, `end_time`, `limit` (1-100), `offset` |
| `GET /api/v1/events/{id}` | UUID |
| `GET /api/v1/indicators` | `type`, `value`, `limit`, `offset` |
| `GET /api/v1/incidents` | `status`, `limit`, `offset` |

## API gaps found (nothing changed yet; each is raised again before the task that needs it)

| Gap | Affects | Workaround now | Smallest fix if needed |
|---|---|---|---|
| No incident detail, no incident-to-events link, no create / status change / notes (list only; the `incident_events` table exists) | Task 5 | list incidents only | `GET /incidents/{id}` returning event ids; `PATCH /incidents/{id}` for status (needs the key) |
| Events cannot be filtered by `url`, `file_hash` or indicator id (only `source_ip`, `domain`) | Tasks 4, 6 | each event embeds its indicators, so match client-side over fetched pages | an `indicator_id` filter on `GET /events` |
| No totals endpoint | Tasks 2, 6 | `total` of a page with `limit=1` is an exact filtered count; trends use one count per time window | `GET /stats` |
| Fixed order: events by `occurred_at` desc, indicators by `last_seen` desc | Tasks 3, 4 | sort the fetched page in the browser | `sort` parameter |
| No free-text search (exact-match filters only) | Task 3 | none | `q` parameter |
| `limit` max 100 | Tasks 2, 4, 6 | page through with `offset` | none needed |
