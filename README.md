# ThreatScope

Unified cyber threat detection and monitoring platform (college project). It collects security events from
domain-squatting detection, a web honeypot, file analysis and network monitoring into **one PostgreSQL database**
behind a **FastAPI** backend.

**Status: Phase 4 (dashboard) implemented on top of Phase 3 (integrations, three of four sources).** The API stores, scores and serves events, and
adapters now collect them from **file analysis, domain look-alike detection (openSquat-derived) and a ModSecurity web
honeypot log**. Network monitoring was evaluated (Zeek) and deferred. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

**Phase 4 adds a browser dashboard** (Streamlit, `dashboard/`): overview, event explorer, indicators, correlation, incident
management and reports, read through the API. See [docs/DASHBOARD.md](docs/DASHBOARD.md).

> The project folder is spelled `ThreaScope` (`F:\ThreaScope`); the product name is ThreatScope. Nothing is renamed.

## What works now

- `POST /api/v1/events` stores one event (needs an API key), extracts indicators (IPs, domains, URLs, hashes), counts
  sightings and gives the event an experimental [risk score](docs/RISK_SCORING.md).
- `GET /api/v1/events` lists events (7 filters, paging, newest first); `GET /api/v1/events/{id}` fetches one.
- `GET /api/v1/indicators` lists indicators.
- Incidents (Phase 4): `GET /api/v1/incidents` lists them, `GET /api/v1/incidents/{id}` returns one with its events,
  `POST /api/v1/incidents` groups existing events into an incident and `PATCH /api/v1/incidents/{id}` changes its status,
  title, notes or events (both writes need the API key). Severity and risk score come from the grouped events.
- `GET /health` reports the API and PostgreSQL **separately** plus overall readiness.
- Interactive API documentation at `http://127.0.0.1:8000/docs`.
- **Adapters** (run in the backend container, each with `--dry-run`; they only call the API, never the database):
  - `python -m integrations.analyse_file PATH...` static file analysis (hashes, type, structure, IPs/domains/URLs; nothing is executed)
  - `python -m integrations.opensquat_adapter --keyword WORD --domains FEED` look-alike domains (typosquats, IDN homographs)
  - `python -m integrations.modsec_adapter AUDIT.log --state STATE.json` ModSecurity attack events, incremental
  - Findings are leads, not verdicts: events say so, and re-running an adapter never stores anything twice.

## Requirements

- Windows with **Docker Desktop** running, and PowerShell. Everything (Python 3.12, PostgreSQL 16) runs in containers;
  nothing needs to be installed on the host.

## Setup (once)

```powershell
Set-Location F:\ThreaScope

# 1. Create .env with random secrets (never printed, never committed)
function New-Hex($n){ $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') }) }
$text = (Get-Content .env.example -Raw) -replace 'INGEST_API_KEY=change-me', "INGEST_API_KEY=$(New-Hex 24)" -replace 'POSTGRES_PASSWORD=change-me', "POSTGRES_PASSWORD=$(New-Hex 16)"
[IO.File]::WriteAllText("$PWD\.env", $text, (New-Object Text.UTF8Encoding($false)))

# 2. Build and start PostgreSQL + the API
docker compose up -d --build
docker compose ps          # db should be (healthy), backend running
```

Settings live in `.env` (see `.env.example` for every name). The API key must be at least 16 characters, must not be a
placeholder such as `change-me`, and must not be repetitive; otherwise the API refuses to start.

## Try it

Fastest way to get events on screen: `.\backend\demo\load-demo.ps1` (add `-DryRun` to only print them). It loads fictional demo
data (look-alike domains, a ModSecurity log with several attacks from one IP, a text note) into the development database;
see `docs/INTEGRATIONS.md` section 7. Or send one event by hand:

```powershell
function Get-EnvValue($n){ ((Get-Content .env | Where-Object { $_ -match "^$n=" }) -replace "^$n=",'') }

Invoke-RestMethod http://127.0.0.1:8000/health            # status ready, api up, database up

$h = @{ "X-API-Key" = (Get-EnvValue INGEST_API_KEY) }
$body = @{ source="honeypot"; external_event_id="demo-001"; event_type="xss_attempt"
           occurred_at="2026-11-07T10:00:00+05:30"; source_ip="203.0.113.42"
           url="http://evil.example/a?q=1"; severity="high"; description="Demo XSS probe"
           metadata=@{ rule="9500001" } } | ConvertTo-Json
$r = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/events -Headers $h -ContentType "application/json" -Body $body
$r.id; $r.risk_score                                       # risk_score 55

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/events/$($r.id)"
(Invoke-RestMethod "http://127.0.0.1:8000/api/v1/events?source=honeypot&limit=10").total
```

Sending the same `source` + `external_event_id` again returns **409** with the existing event's id; omitting the key
returns **401**.

### Event fields (the common format)

| Field | Notes |
|---|---|
| `source` | `domain`, `honeypot`, `file` or `network` (required) |
| `event_type` | lower-case text such as `xss_attempt` (required) |
| `occurred_at` | when it really happened; ISO-8601 **with a timezone** (required); stored as UTC |
| `severity` | `info`, `low`, `medium`, `high`, `critical` (required) |
| `description` | 1-2000 characters (required) |
| `external_event_id` | your own id; same source + same id = duplicate (optional) |
| `source_ip`, `destination_ip` | IPv4/IPv6 (optional) |
| `domain`, `url`, `file_hash` | normalised on the way in: punycode lower-case domain, ASCII http/https/ftp URL, lower-case SHA-256 |
| `metadata` | JSON object, at most 64 KB (`MAX_METADATA_BYTES`) and 10 levels deep (optional) |

The server adds `id` (UUID), `received_at`, `risk_score`, `risk_factors` and `indicators`. Clients cannot send those.

### List filters

`source`, `event_type`, `severity`, `source_ip`, `domain`, `start_time` (inclusive), `end_time` (exclusive; both need a
timezone), `limit` (default 50, maximum 100), `offset`. All matches are exact; `%` and `_` are ordinary characters.

### Errors

Every error looks like `{"error": {"code": "...", "message": "...", "details": {...}}}`: 401 `unauthorized`,
404 `not_found`, 409 `duplicate_event`, 422 `validation_error` / `invalid_filter`, 503 `database_error`, 500 `internal_error`.
Responses never contain SQL, stack traces, credentials or the value you sent.

## Tests

```powershell
docker compose run --rm backend pytest -q                    # everything: SQLite + real PostgreSQL (1147 tests)
docker compose run --rm backend pytest -q -m "not postgres"  # quick loop (SQLite only)
docker compose run --rm backend pytest -q -m postgres        # PostgreSQL-only tests
```

- Database and API tests run twice: on in-memory SQLite (fast) and on **real PostgreSQL**. The PostgreSQL tests are
  mandatory: if the database is down they **error, they are never skipped**.
- They use a separate database, `<POSTGRES_DB>_test` (default `threatscope_test`). A guard refuses to drop tables or
  create databases unless the name ends in `_test` and differs from the development database.
- Tests never use the real API key from `.env`.

## Security notes

- `.env` is git-ignored and was never committed. `.env.example` contains placeholders only.
- The API key is read from `INGEST_API_KEY`, compared in constant time, and never logged or returned. Secrets are masked
  (`**********`) in settings output and replaced with `***` in logs.
- **Local-only by design.** Docker publishes ports 8000 and 5432 on `127.0.0.1` only. **Read endpoints are
  intentionally unauthenticated for this local MVP** and there is no TLS. Never expose the API to a network, forward the
  port, or change the port mapping to `0.0.0.0`. Add authentication and TLS first if that is ever needed.
- Original reference repositories are never modified; see `third_party/NOTICE.md` for attribution and licences. openSquat
  logic is adapted under GPL-3.0 with its notice kept; nothing is copied from the honeypot project (licence unverified).
- Adapters never log or store the API key, request/response bodies, cookies or rule payloads. Their end-to-end tests run a
  real server on the **test** database and scan stored data and the server log for secrets.
- Docker's data file lives on C:. If C: is nearly full, free space before building or pulling images.

## Database and `create_all` (limitations)

Tables are created at startup with SQLAlchemy `create_all`, which **only creates missing tables**. It cannot alter an
existing table, keeps no history and cannot roll back. If a model changes after tables exist, the existing database does
not change by itself. Resetting the development database means `docker compose down -v`, which **deletes all stored
data**: only do that deliberately, never casually.
The database layer is ready for Alembic: one `Base.metadata`, a constraint naming convention, and `init_db()` as the only
function that creates tables (replace it with `alembic upgrade head` later).

Tables: `events`, `indicators`, `event_indicators`, `incidents`, `incident_events`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `failed to connect to the docker API` | Start Docker Desktop and wait for "Engine running". |
| `port is already allocated` (5432) | Set `POSTGRES_HOST_PORT=5433` in `.env`, then `docker compose up -d`. |
| API container exits; log shows `ValidationError ... ingest_api_key` | Put a random key of 16+ characters in `.env` (see Setup). |
| `password authentication failed` after editing `.env` | PostgreSQL keeps the password it was first created with. Restore the old password in `.env`; resetting needs `docker compose down -v`, which deletes all data, so only do it deliberately. |
| `401 unauthorized` | Send the header `X-API-Key` with the value of `INGEST_API_KEY`. |
| `409 duplicate_event` | That `source` + `external_event_id` was already stored; `details.existing_id` is the stored event. |
| `422 validation_error` | Read `details`: each entry names the field (`loc`) and the problem. |
| Tests error with "PostgreSQL is mandatory ..." | `docker compose up -d db`, then re-run. |
| `no space left on device` / Docker I/O errors | The disk holding Docker's image is full. Free space, restart Docker Desktop. |

## Project layout

```
backend/app/        config.py  db.py  enums.py  errors.py  logging_config.py  main.py
  models/           the five tables       schemas/   the API contract (Pydantic)
  services/         event_service, indicator_extractor, risk_scoring, ...      api/   thin routers
backend/integrations/  client, config, file analyser, openSquat adapter, ModSecurity adapter   (Phase 3)
backend/tests/      unit/  db/  api/  integrations/      (SQLite + PostgreSQL)
docs/               INTEGRATIONS.md  NETWORK_DECISION.md  PHASE1_AUDIT.md  DEVLOG.md  RISK_SCORING.md  superpowers/
third_party/NOTICE.md   attribution
```

`docs/DEVLOG.md` explains every file in plain language for the viva.

## Licence

GNU General Public License v3.0 (see `LICENSE`). Third-party notices: `third_party/NOTICE.md`.

## Dashboard

```powershell
Set-Location F:\ThreaScope\dashboard
pip install -r requirements.txt   # once, on the host
streamlit run app.py              # http://127.0.0.1:8501 (the API must be running: docker compose up -d)
```

Set `INGEST_API_KEY` (the same value as the API's) to allow creating and editing incidents; without it the dashboard is read-only.
