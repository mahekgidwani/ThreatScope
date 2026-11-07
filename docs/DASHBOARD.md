# ThreatScope Phase 4: dashboard

A browser dashboard for ThreatScope: overview, event investigation, indicators, correlation, incident management and reports, all read from the
real FastAPI backend (never from PostgreSQL directly, never from hardcoded data).

```
Dashboard (Streamlit, Windows host, 127.0.0.1:8501) -> ts_dashboard.api_client -> FastAPI (127.0.0.1:8000) -> services -> PostgreSQL
```

## Run it

```powershell
Set-Location F:\ThreaScope
docker compose up -d                       # PostgreSQL + API (already running if you did Phase 2/3)
pip install -r dashboard\requirements.txt  # once: streamlit, plotly, httpx, pydantic (host Python)
Set-Location dashboard
streamlit run app.py                       # http://127.0.0.1:8501  (open the root URL, not /events)
```

Optional configuration (environment or `.env`, same names the adapters use): `THREATSCOPE_API_URL` (default `http://127.0.0.1:8000`),
`THREATSCOPE_TIMEOUT_SECONDS` (default 10), and `INGEST_API_KEY` (turns on incident editing; without it the dashboard is read-only).

## Tests

| Command | What it runs |
|---|---|
| `cd dashboard; python -m pytest -q` | all mocked tests on the host (fake API, Streamlit AppTest) |
| `docker compose run --rm --no-deps -v "${PWD}\dashboard:/dash" -w /dash backend pytest -q --ignore=tests/ui` | the Streamlit-free tests on Python 3.12 in the existing backend image |
| `cd dashboard; python -m pytest -q -m live` | **integration**: dashboard code against the real running API and PostgreSQL (read-only; fails, never skips, if the backend is down) |
| `docker compose run --rm backend pytest -q` | Phase 2, Phase 3 and the new incident API tests, SQLite and PostgreSQL |

## Layout

```
dashboard/
  app.py                     theme, sidebar navigation (st.navigation)
  views/                     one module per page (+ common.py: client, header); the only code that imports Streamlit
  ts_dashboard/              logic with no Streamlit import, so it is testable and reusable
    config.py  api_client.py  models.py  redact.py        settings, the one HTTP client, validated API shapes, secret hiding
    overview.py events.py indicators.py correlation.py incidents.py reports.py paging.py    data side of each page
    components.py theme.py charts.py                      escaped HTML parts, design tokens + CSS, Plotly figures
  tests/ (mocked)  tests/ui/ (AppTest)  tests/live/ (real stack)  tests/fake_backend.py (in-memory API with the real rules)
  .streamlit/config.toml     127.0.0.1 only, no telemetry, dark base theme
```

## Rules (each one is enforced by a test)

1. HTTP only. The dashboard imports no backend code, no SQLAlchemy, no database driver; only `api_client.py` touches the network; Plotly only in `charts.py`.
2. **The API key is optional and used only for incident writes.** Every read is an open `GET`. Creating and editing incidents needs `X-API-Key`, so the dashboard reads
   `INGEST_API_KEY` if present. It is a `SecretStr`, sent only as that header by two client methods, scrubbed from error text, and never rendered or logged.
3. No cache: a page shows what was just read from the API; when the API fails it shows the error, never old data as live.
4. All event text is HTML-escaped before display; metadata, URLs and CSV cells have secrets hidden; CSV cells cannot run as spreadsheet formulas.
5. Risk scores are shown as computed by the backend with "Experimental prioritisation score - not a probability of compromise." No scoring logic exists in the dashboard.
6. Streamlit is bound to `127.0.0.1`; nothing is exposed publicly.

## Pages

| Page | Shows |
|---|---|
| Overview | 5 KPI cards, events over time / by severity / by source, recent events, top recurring indicators, recent high-risk activity |
| Events | search (ID, IP, domain), filters, both sort orders, paging, event detail with risk factors, redacted metadata, related events |
| Indicators | filter and sort indicators, related events, "an indicator is not a verdict" |
| Correlation | indicators shared by 2+ events, cross-source tag, relationship graph, event IDs |
| Incidents | status cards, list, detail, status / title / notes, add or remove events, create from a shared indicator or event IDs |
| Reports | scoped summary, high-risk events, recurring indicators, CSV export, Markdown reports |
| System status | API and database health |

## Endpoints used

| Endpoint | Auth | Parameters |
|---|---|---|
| `GET /health` | no | 200 ready, 503 database down (both have a body) |
| `GET /api/v1/events` | no | `source`, `event_type`, `severity`, `source_ip`, `domain`, `start_time`, `end_time`, `limit` (1-100), `offset` |
| `GET /api/v1/events/{id}` | no | UUID |
| `GET /api/v1/indicators` | no | `type`, `value`, `limit`, `offset` |
| `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}` | no | `status`, `limit`, `offset` / the incident with its events |
| `POST /api/v1/incidents`, `PATCH /api/v1/incidents/{id}` | key | added in Phase 4 Task 5 (backend extension, below) |

## Known limits and gaps

| Limit | What the dashboard does | Smallest fix if it matters |
|---|---|---|
| Events cannot be filtered by `url`, `file_hash` or indicator id | groups the newest 1,000 events (each embeds its indicators); every page says "searched the newest N of M" | an `indicator_id` filter on `GET /events` |
| No totals endpoint | `total` of a `limit=1` query is an exact filtered count; trends are bucketed from the newest 500 events | `GET /stats` |
| The API only sorts newest first | "oldest first" is computed exactly from `total` and `offset`; other sorts cover the fetched set and say so | a `sort` parameter |
| No free-text search | exact event ID, source IP or domain only | a `q` parameter |
| Incident notes are the single `summary` field | edited as "Investigation notes"; no history | a notes table |
| Network monitoring is deferred (Phase 3 decision) | the Network source shows 0 | out of scope |
| `limit` is capped at 100 | pages through with `offset` | none needed |

## Task 2: shell, theme and Overview

- Navigation: `st.navigation` with seven entries (Overview, Events, Indicators, Correlation, Incidents, Reports, System status).
- Look: dark navy console, one cyan accent, severity colours reserved for severity and always paired with a text label.
  Tokens live in `ts_dashboard/theme.py` (single source for CSS and charts). System font stack (Source Sans Pro, bundled with Streamlit, so every machine and the data grid draw the same face).
- Streamlit strips inline `style` attributes from markdown HTML, so colours are CSS classes (`sev-high`, ...).
- All event text is HTML-escaped before it reaches the page (`components.py`, tested with hostile input).
- Overview numbers: totals, per-severity and per-source counts are exact (`total` of `limit=1` queries). The trend and recent lists use the newest 500
  events and the page says so when that is fewer than all events. "Recurring" = sighting count above 1, among the 300 most recently seen indicators.
- Tests: `tests/fake_backend.py` is an in-memory API with the real filter, order and paging rules; `tests/ui/` runs the real app with Streamlit AppTest and needs the host
  packages (streamlit, plotly). The rest also runs on Python 3.12 in the backend image with `--ignore=tests/ui`.

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
