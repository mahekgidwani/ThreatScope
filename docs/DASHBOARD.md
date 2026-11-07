# ThreatScope Phase 4: dashboard

Streamlit dashboard that reads real data from the FastAPI backend. Done: Task 1 (foundation), Task 2 (shell, theme, Overview, System status), Task 3 (Events Explorer), Task 4 (Indicators and Correlation), Task 5 (Incident Management), Task 6 (Reports and exports).

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
2. **The API key is optional, and used only for incident writes.** Every read is an open `GET`. Creating and editing incidents needs `X-API-Key`,
   so the dashboard reads `INGEST_API_KEY` (same `.env` as the API) if present; without it the dashboard is read-only and says so. The key is a
   `SecretStr`, sent only as that header by two client methods, scrubbed from error text, and never rendered (tests enforce each point).
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
| ~~No incident detail, link to events, create, status change or notes~~ | Task 5 | **Closed in Task 5** (see below) | |
| Events cannot be filtered by `url`, `file_hash` or indicator id (only `source_ip`, `domain`) | Tasks 4, 6 | each event embeds its indicators, so match client-side over fetched pages | an `indicator_id` filter on `GET /events` |
| No totals endpoint | Tasks 2, 6 | `total` of a page with `limit=1` is an exact filtered count; trends use one count per time window | `GET /stats` |
| Fixed order: events by `occurred_at` desc, indicators by `last_seen` desc | Tasks 3, 4 | sort the fetched page in the browser | `sort` parameter |
| No free-text search (exact-match filters only) | Task 3 | none | `q` parameter |
| `limit` max 100 | Tasks 2, 4, 6 | page through with `offset` | none needed |

## Task 2: shell, theme and Overview

- Navigation: `st.navigation` with seven entries; Events, Indicators, Correlation, Incidents and Reports are placeholders until their task.
- Look: dark navy console, one cyan accent, severity colours reserved for severity and always paired with a text label.
  Tokens live in `ts_dashboard/theme.py` (single source for CSS and charts). System font stack (Source Sans Pro, bundled with Streamlit, so every machine and the data grid draw the same face).
- Streamlit strips inline `style` attributes from markdown HTML, so colours are CSS classes (`sev-high`, ...).
- All event text is HTML-escaped before it reaches the page (`components.py`, tested with hostile input).
- Overview numbers: totals, per-severity and per-source counts are exact (`total` of `limit=1` queries). The trend and recent lists use the newest 500
  events and the page says so when that is fewer than all events. "Recurring" = sighting count above 1, among the 300 most recently seen indicators.
- Tests: `tests/fake_backend.py` is an in-memory API with the real filter, order and paging rules; `tests/ui/` runs the real app with Streamlit AppTest and needs the host
  packages (streamlit, plotly). The rest (101 tests) also runs on Python 3.12 in the backend image with `--ignore=tests/ui`.

## Task 3: Events Explorer

- **Search** accepts exactly what the API can do: an event ID (opens its detail), a source IP (exact, canonicalised) or a domain (exact). File hashes and URLs
  are refused with a reason, because `GET /events` has no filter for them (see the gap table; Task 4 revisits this).
- **Filters**: source, severity, event type (types seen in the newest 500 events), time range in UTC (presets or whole UTC days), sort, rows per page, Clear filters.
- **Sort by occurrence time** both ways although the API only sorts newest first: "oldest first" page *k* is the slice at `offset = total - (k+1)*size`, reversed
  (`events.fetch_event_page`), so it is the true oldest page, not the newest page flipped. A page past the end is clamped to the last page.
- **Detail** (choose an event under the table, or search its ID): every field, risk score with the API's risk factors and the experimental-score label, the event's
  indicators, metadata with secrets hidden (`redact.py`), and other events sharing its source IP or domain.
- The table is the same HTML table as the Overview (escaped, severity badges). Streamlit's canvas data grid was tried and dropped: it drew in a fallback serif
  font and could not show severity badges.
- Opening `/events` directly on a freshly started server can flash "Page not found" once (Streamlit registers pages when the app first runs). Open the root URL.

## Task 4: Indicator Explorer and Correlation (no backend change)

- **Indicators**: filter by type and exact value; sort by most recently seen (the API order), most sightings, or newest first seen. The last two are not API orders,
  so they read up to 1,000 indicators and sort here; the page says so when there are more. Selecting an indicator shows its fields and the events that mention it.
  The page states that an indicator is an observation, not a verdict.
- **Correlation** reads the newest 1,000 events once (every event already carries its extracted indicators) and groups them: an indicator in 2+ events is a
  *shared indicator*. Nothing is scored or guessed. Table columns: type, value, events, sources (with a `cross-source` tag), highest severity, max risk, latest time.
  Filters: indicator type, minimum events, only indicators seen by more than one source. The selected indicator gets a relationship graph (indicators left, events
  right, one line per stored membership, events coloured by severity, other shared indicators of the same events included so chains are visible) and the list of
  events with their IDs.
- **Why no API change**: the API has no events-by-indicator filter for URLs and hashes, but each event embeds its indicators, so grouping in the dashboard is exact
  for the events it reads. The limit is the scan size: with more than 1,000 events, older ones are not searched, and every page says "searched the newest N of M".
  If the project outgrows that, the smallest fix is an `indicator_id` filter on `GET /api/v1/events` (one join on `event_indicators`, read-only).
- Tests use the in-memory fake API; the graph edges are tested to equal the stored memberships exactly (nothing invented).

## Task 5: Incident Management (small backend extension)

**Why the backend changed.** The API could only list incidents. Viewing an incident's events, grouping events and tracking status are impossible without
detail and write endpoints, and the database already had the tables (`incidents`, `incident_events`). The additions are small, additive and need no schema change:

| Endpoint | Auth | Does |
|---|---|---|
| `GET /api/v1/incidents/{id}` | none | the incident plus its events (newest first, with indicators); 404 if unknown |
| `POST /api/v1/incidents` | key | `{title, summary?, event_ids[1..100]}` creates an `open` incident; unknown event = 404, nothing created |
| `PATCH /api/v1/incidents/{id}` | key | any of `status`, `title`, `summary` (empty clears), `add_event_ids`, `remove_event_ids`; an incident keeps at least one event |

- Severity and risk score are **not** accepted from clients: they are the highest severity and the highest event risk score among the grouped events, recomputed when
  membership changes. No second scoring formula exists. `IncidentOut` gained `event_count`, a query-time count (no new column).
- Notes live in the existing `summary` column (the dashboard calls it "Investigation notes"); there is no separate notes table, so no notes history.
- Backend code touched: `models/incident.py`, `schemas/incident.py`, `services/incident_service.py`, `api/incidents.py`. 78 new tests run on SQLite and PostgreSQL
  (`backend/tests/api/test_incidents_api.py`); the earlier 1,147 still pass unchanged.

**Dashboard.** Summary cards by status; a filterable, paged list; incident detail (fields, events with copyable IDs, the experimental-score label); a form to change
status, title and notes; add events by pasted ID or remove them; and "Create an incident" from a shared indicator (the correlation view's grouping) or from event IDs.
Without `INGEST_API_KEY` every control that writes is replaced by a "Read-only" explanation and nothing is sent. An incident is a work item, not a confirmed attack.

## Task 6: Reports and exports (no backend change)

- **Scope**: time range (UTC), source, severity. Every number below it follows the scope.
- **Exact**: events in scope, the split by severity and by source (each is the `total` of a filtered `limit=1` query), incident counts by status (not scoped).
- **From a sample** (the newest 1,000 events in scope; the page and the report say "the newest N of M" when it is fewer): most frequent event types and recurring
  indicators (in 2+ events of the scope, next to their all-time sighting count). **High-risk events** are the highest-risk of the newest 200 critical and 200 high events.
- **Downloads**: a Markdown summary report; an events CSV (up to 5,000 newest in scope, prepared on demand and invalidated when the scope changes); and a Markdown
  investigation summary for any incident (notes, events with IDs, indicators its events share).
- **CSV safety**: UTF-8 with BOM (Excel reads accents), UTC ISO times, one row per event with indicators and metadata JSON. Any cell that starts with `= + - @`, tab or
  CR gets a leading apostrophe so a spreadsheet cannot run it as a formula; secrets in description, URL, indicators and metadata are hidden (`redact.py`).
- Risk scores always appear with "Experimental prioritisation score — not a probability of compromise"; reports never call anything confirmed or malicious.
