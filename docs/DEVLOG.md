# ThreatScope development log

Plain-language record of what was built, why, how it works and how to test it (for the viva).

## Phase 1 - Repository audit
Read-only audit of openSquat, OWASP Honeypot-Project and FAME. See `PHASE1_AUDIT.md`.

## Phase 2 - Backend foundation
Design: `superpowers/specs/2026-11-07-threatscope-phase2-backend-design.md`
Plan: `superpowers/plans/2026-11-07-threatscope-phase2-backend.md`

### Task 1 - Repository foundation (done)
Created the git repo, `.gitignore` (written before anything else so `.env` can never be committed),
`.env.example` (placeholders only), GPL-3.0 `LICENSE` and `third_party/NOTICE.md` (attribution).

### Task 2 - Docker, dependencies and PostgreSQL (done)
What: `docker-compose.yml` (PostgreSQL 16 + backend), `backend/Dockerfile` (Python 3.12, non-root user),
`backend/requirements*.txt`, `backend/pytest.ini`, and a local `.env` with random secrets (git-ignored).
Why: running everything in containers gives every machine the same Python and database versions.
How it works: the `db` service stores data in the Docker volume `pgdata`; its healthcheck uses `pg_isready`;
ports are published on `127.0.0.1` only so nothing outside this computer can reach them.
Resolved versions inside the container: Python 3.12.16, FastAPI 0.162.0, SQLAlchemy 2.0.57,
Pydantic 2.14.3, psycopg 3.3.8, pytest 8.4.2, httpx 0.28.1; database PostgreSQL 16.15 (Debian).
Verified: `docker compose ps` shows `db (healthy)`; `docker compose port db 5432` = `127.0.0.1:5432`;
the backend container connected to `db` over the compose network (`select 1` returned 1).
Common errors: Docker engine not running (start Docker Desktop); port 5432 taken (set `POSTGRES_HOST_PORT`).
Incident: the C: drive filled up while Docker was pulling images, which left Docker's local copy of the
newest Alpine base layer corrupt (`exec format error`, even for a freshly pulled `alpine:latest`). Ruling: use the
Debian `postgres:16` image instead of `postgres:16-alpine`. Same PostgreSQL major version, larger image. Docker
Desktop was restarted by the user; no volumes or data were deleted. Only the broken `postgres:16-alpine` and
`alpine:latest` images were removed and `alpine`-based images should be re-checked if they are needed later.

### Task 10 - Documentation and full verification (done)
Files: `README.md` (setup, usage, tests, security notes, troubleshooting), `docs/RISK_SCORING.md` (the scoring rule with worked
examples), this log. Nothing in the application code changed in this task.
Evidence (all from real runs, 2026-11-07):
- `docker compose run --rm backend pytest -q` -> **575 passed** (SQLite + PostgreSQL), 0 skipped.
- `... pytest -q -m "not postgres"` -> 416 passed. `... pytest -q -m postgres` -> 159 passed.
- Fail-not-skip: with `docker compose stop db`, the 159 PostgreSQL tests all **errored** ("PostgreSQL is mandatory for these tests
  but is not reachable"), exit code 1; none were skipped. `docker compose start db` restored it.
- Localhost-only: `docker compose port backend 8000` = `127.0.0.1:8000`; `docker compose port db 5432` = `127.0.0.1:5432`;
  `Get-NetTCPConnection` shows both listeners on `127.0.0.1` only.
- Start-up log shows the database URL with the password hidden: `postgresql+psycopg://threatscope:***@db:5432/threatscope`.
- Live round trip against the real stack: `/health` 200 ready; POST without key 401; POST with key 201 (`occurred_at`
  converted to `04:30:00Z`, `risk_score` 55 = 40 + 15 + 0, three indicators); GET by id returned exactly the POST body; list with
  `source=honeypot` total 1; the same POST again 409 with `existing_id` equal to the stored id; a second event from the same IP
  got `risk_score` 60 (+5, second sighting) and every indicator's `sighting_count` became 2; a bad IP with secret-looking text
  gave 422 and the response did not echo it; `limit=101` 422; unknown id 404; `domain=%25` 422 `invalid_filter`; `/docs` 200.
- Database (dev, `threatscope`): `\dt` lists exactly `event_indicators, events, incident_events, incidents, indicators`; 2 events,
  3 indicators, 6 links, 0 incidents; `events` carries the named constraints `pk_events`, `uq_events_source_external_event_id`,
  `ck_events_source_valid`, `ck_events_severity_valid`, `ck_events_risk_score_range`. The test database `threatscope_test` is separate.
- Outage test: after `docker compose stop db`, `/health` answered 503 `{"status":"not_ready","api":{"status":"up"},"database":
  {"status":"down","latency_ms":null}}`, `/docs` still 200, and `GET /api/v1/events` gave a clean 503 `database_error` with no internals.
  After `docker compose start db`, `/health` was 200 ready again and both events were still there (data volume kept). The log
  recorded `database check failed (OperationalError)` - the error type only.
- Observation: the 503 `/health` answer took about 4.1 s with the container stopped (Docker's name lookup for the stopped `db`
  plus the 2-second connect timeout). Correct, but not instant.
- Two demo events (`demo-001`, `demo-002`) now exist in the development database from the manual round trip.
Deviations from the plan are listed in the ledger (`Ruling:` lines) and in each task's entry above.

### Task 9 - Health endpoint (done)
Files: `backend/app/api/health.py` (registered in `main.py`), tests `tests/api/test_health.py`.
`GET /health` returns `{"status": "ready" | "not_ready", "api": {"status": "up"}, "database": {"status": "up" | "down", "latency_ms": ...}}`.
The API and the database are reported separately: if the code runs at all the API is up; the database is checked with
`SELECT 1` (2-second connect timeout). Both up = HTTP 200 `ready`; database unreachable = HTTP 503 `not_ready` with
`database.status = "down"` and `latency_ms = null`. The body never contains driver names, host names, user names,
passwords or error text - the reason goes to the log (error type only). It needs no API key and is sent with
`Cache-Control: no-store` so a proxy never serves a stale answer. Why it matters: Docker, load balancers and the dashboard use
this to know when the system is really usable.
Tests: 18 (9 cases on SQLite and on PostgreSQL), including a database that refuses connections (port 1) to prove the 503
path, a check that the response and the log contain no credentials, and a speed check (< 5 s). Mutation check: forcing
"ready" made the 503 test fail. Full suite 575 passed.
Command: `docker compose run --rm backend pytest -q tests/api/test_health.py`.
Manual check against the running stack (stop and start `db`) is done in Task 10.

### Task 8 - REST API, API-key auth and uniform errors (done)
Files: `backend/app/main.py` (app factory), `app/api/{deps,events,indicators,incidents}.py`, `app/errors.py` (now also maps
errors to responses), tests `tests/api/{test_events_api,test_read_api,test_startup}.py`, `client` fixture in `tests/conftest.py`.
Endpoints: `POST /api/v1/events` (needs header `X-API-Key`), `GET /api/v1/events` (filters, paging), `GET /api/v1/events/{id}`,
`GET /api/v1/indicators`, `GET /api/v1/incidents`; interactive docs at `/docs`. Routers contain no queries: they parse input,
call a service, and shape the response.
Security: the key comes from `INGEST_API_KEY`, is compared with `hmac.compare_digest`, and is never logged or returned. Reads
are open on purpose for the local MVP (ports are published on 127.0.0.1 only). The request log line is
`METHOD /path STATUS duration` - no query string, headers or body. At startup the app loads the settings (a missing, weak or
placeholder key stops it), turns on secret-redacting logging and creates missing tables.
Errors: every error has the shape `{"error": {"code", "message", "details"}}`: 401 unauthorized, 404 not_found (also unknown
routes), 405, 409 duplicate_event (with the existing id), 422 validation_error / invalid_filter, 503 database_error (database
unreachable), 500 internal_error. Responses never contain SQL, stack traces, credentials or the submitted value; those go to the
log. Validation details are only `{loc, type, msg}`.
Found while testing: Python's own "invalid IP" message repeated the input, so the schema now raises its own message.
Tests: 3 new test files and 171 new test cases (suite went 386 -> 557; every API test runs on SQLite and on PostgreSQL). Mutation checks: disabling auth + echoing
input made 12 tests fail; skipping startup work made 5 fail. Command: `docker compose run --rm backend pytest -q`.
Known: test output shows one warning from FastAPI's test client about httpx (tooling, not our code).

### Task 7 - Services: create, get and list events (done)
Files: `backend/app/errors.py`, `app/services/{event_service,indicator_service,incident_service,paging}.py`; tests
`tests/unit/test_errors.py`, `tests/db/test_event_service.py`, `tests/db/test_concurrency_pg.py`; one line added to
`app/models/event.py` (indicators come back in a stable order).
`errors.py`: our own exceptions (duplicate 409, not found 404, bad API key 401, invalid filter 422). Task 8 turns them into
JSON error responses.
`create_event` (one database transaction): (1) insert the event; a duplicate (same source + external_event_id) is rejected
here by the UNIQUE constraint and reported as `DuplicateEventError` carrying the existing event's id; any other integrity
error is NOT disguised as a duplicate. (2) For each indicator run `UPDATE ... SET sighting_count = sighting_count + 1
RETURNING ...` - a single atomic statement, so concurrent requests never lose a count; new indicators are inserted inside a
SAVEPOINT so losing a creation race only undoes the savepoint. Indicators are always processed in sorted (type, value)
order so two requests can never lock each other in a circle (deadlock). (3) Score the event (`prior_sightings` = highest
returned count - 1, so the event itself is never counted), link the indicators, commit. Any failure rolls everything back.
`get_event` / `list_events`: exact-match filters (source, event_type, severity, source_ip, domain, start_time, end_time),
newest first with id as tie-break so paging is stable, limit 1-100, offset >= 0, `start_time` inclusive / `end_time`
exclusive, naive times and start > end rejected. IP and domain filters are normalised exactly like ingestion
(`BÜCHER.example` finds `xn--bcher-kva.example`). No SQL LIKE anywhere, so `%` and `_` are ordinary characters.
Tests: 78 (service behaviour on SQLite and PostgreSQL, plus 3 PostgreSQL-only races: 8 simultaneous identical
external ids -> exactly 1 success and 7 clean conflicts; 8 simultaneous events sharing a domain -> sighting_count 8 and
exact bonus sequence; opposite-order indicators -> no deadlock). Mutation checks: a read-then-write counter made 2
concurrency tests fail; removing the sorted order made the deadlock test fail 3 times out of 3. Concurrency tests passed
5 runs in a row after restoring.
Command: `docker compose run --rm backend pytest -q`.

### Task 6 - Indicator extraction and experimental risk score (done)
Files: `backend/app/services/{indicator_extractor,risk_scoring}.py`, tests `tests/unit/test_indicator_extractor.py`
and `tests/unit/test_risk_scoring.py`. Both modules are pure functions: no database, no web framework.
Indicator extractor: an "indicator" is a value worth matching across events (an IP, domain, URL or file hash).
`extract_indicators(event)` returns them in a fixed order, each once: source IP, destination IP, domain, URL, the URL's
host, file hash. The URL's host becomes a domain indicator (or an IP indicator if the host is an IP). The destination IP
counts only for `network` events: for honeypot events it is our own address, and using it would make every attack look
related to every other. A host that is not a valid hostname (for example `_dmarc.example`) is skipped, the URL itself is
still kept, and ingestion never fails because of it.
Risk score (experimental, rule-based): `compute_risk(severity, source, prior_sightings)` returns `(score, factors)`.
Points: severity info 0 / low 10 / medium 25 / high 40 / critical 55; source honeypot 15 / file 10 / domain 5 / network 5;
repeat bonus +5 for each EARLIER event that mentioned the same indicator, capped at +20. `prior_sightings` never counts the
event being scored, so the first sighting gets +0, the second +5, the third +10, the fifth and later +20. Examples:
`high` honeypot first sighting = 40 + 15 + 0 = 55; `critical` honeypot first sighting = 70; the highest possible is 90.
`factors` lists every line of the sum so the score can be explained. It is a prioritisation aid, not a probability of
compromise, and it is separate from `severity`.
Tests: 79 (extractor 17 cases, scoring incl. the whole schedule 0/5/10/15/20/20/20). Mutation check: counting the current
event as a prior sighting and ignoring the network-only rule made 36 tests fail; restored, all pass.
Command: `docker compose run --rm --no-deps backend pytest -q tests/unit`.

### Task 5 - Pydantic schemas: the API contract (done)
Files: `backend/app/schemas/{common,event,indicator,incident,health}.py`, tests `tests/unit/test_event_schema.py`
and `tests/unit/test_output_schemas.py`.
What it is: Pydantic classes that describe exactly what a client may send (`EventIn`) and what the API returns
(`EventOut`, `IndicatorOut`, `IncidentOut`, `Page`, `HealthOut`, `ErrorResponse`). FastAPI uses them to validate input
automatically and to build the `/docs` page.
Why strict: bad data is cheapest to stop at the door. `EventIn` rejects unknown fields and the server-owned ones
(`id`, `received_at`, `risk_score`, `risk_factors`), so a client cannot fake a risk score.
Normalisation (the same thing always has one spelling): times become UTC and must carry a timezone (naive times and
Unix numbers, even as text, are refused); IPs use the canonical form (`2001:0DB8:0:0:0:0:0:1` -> `2001:db8::1`);
domains become lower-case punycode without a trailing dot (`Bücher.Example.` -> `xn--bcher-kva.example`; a Cyrillic
look-alike `аpple.com` becomes a visibly different `xn--` name); hashes become lower-case; URLs must be ASCII,
http/https/ftp, have a host, no spaces or control characters, at most 1024 characters.
Metadata: plain JSON only (no NaN, no custom objects), at most `MAX_METADATA_BYTES` counted in bytes, and at most 10
levels deep (see Rulings in the ledger: a 5,000-level-deep object was small enough to pass the size check but could
break serialising the event back out).
`EventOut` reads the database model directly (`from_attributes`) and exposes `event_metadata` under its API name
`metadata`. `normalise_domain` is public so the list endpoint's `domain` filter uses the same rules as ingestion.
Tests: 101 schema tests. Command: `docker compose run --rm --no-deps backend pytest -q tests/unit`.
Known limits: URLs are stored exactly as sent (scheme/host are not lower-cased); domains must be valid hostnames, so
names starting with an underscore (e.g. `_dmarc.example.com`) are rejected.

### Task 4 - Database layer and the five tables (done)
Files: `backend/app/enums.py`, `app/db.py`, `app/models/{types,event,indicator,incident,__init__}.py`;
tests: `tests/db/test_constraints.py`, `tests/db/test_db_layer.py`, `tests/unit/test_db_guard.py`;
test helpers: `tests/db_guard.py`, `tests/db_support.py`, fixtures in `tests/conftest.py`, `tests/**/__init__.py`.
`enums.py`: the allowed words (source, severity, indicator type, incident status). The database stores them as text and
CHECK constraints reject anything else.
`db.py`: `Base` (parent of all tables) with a naming convention so every constraint and index gets a predictable name
(this is what makes a later move to Alembic easy); `make_engine` (PostgreSQL gets a 2-second connect timeout);
`get_engine` (built once from settings); `get_db` (one session per request, rollback on error, always closed);
`init_db` (the only place that creates tables, using `create_all`); `check_db` (runs `SELECT 1`, never raises,
logs only the error type).
Tables (`models/`): `events` (UNIQUE source + external_event_id; CHECKs on source, severity, risk 0-100; 5 indexes),
`indicators` (UNIQUE type + value; sighting_count >= 1), `event_indicators` and `incident_events` (composite primary keys
so a link can exist only once; ON DELETE CASCADE), `incidents` (status/severity/risk CHECKs). Times use `UtcDateTime`:
always timezone-aware UTC, naive datetimes are refused. Metadata is JSONB on PostgreSQL. The Python attribute
`Event.event_metadata` maps to the column `metadata` because `metadata` is reserved by SQLAlchemy.
Tests: every database test runs twice, on in-memory SQLite (fast) and on real PostgreSQL 16. PostgreSQL tests use the
separate database `threatscope_test`, never the development database `threatscope`. `db_guard.py` refuses to drop
tables or create databases unless the name matches `[A-Za-z0-9_]+_test` and differs from the dev database; it runs
before any connection is made. If PostgreSQL is down the PostgreSQL tests show as ERROR (never skipped).
Commands: `docker compose run --rm backend pytest -q` (everything) or `... pytest -q -m "not postgres"` (quick loop).
Result: 128 passed (98 without PostgreSQL, 30 PostgreSQL-only). Dev database `threatscope` still has 0 tables; the test
database has exactly the five. Mutation check: with the guard disabled, 12 guard tests failed; guard restored, 13 pass.
Common errors: `PostgreSQL is mandatory ...` = start the database (`docker compose up -d db`); `IntegrityError` in tests is
usually the point of the test (a constraint doing its job).

### Task 3 - Configuration and logging (done)
Files: `backend/app/config.py`, `backend/app/logging_config.py`, `backend/app/__init__.py`,
`backend/tests/conftest.py`, `backend/tests/unit/test_config.py`, `backend/tests/unit/test_logging_config.py`,
and `pythonpath = .` added to `backend/pytest.ini`.
What `config.py` does: reads settings from environment variables (and the `.env` file) into one `Settings` object
using Pydantic Settings. Names match `.env.example`. Unknown keys such as `POSTGRES_HOST_PORT` (used only by
Docker Compose) are ignored. Rules: API key is required, at least 16 characters, no leading/trailing spaces,
not a placeholder (`change-me`, `changeme`, `your-api-key`, anything containing `password`) and not repetitive
(fewer than 6 different characters). Port must be 1-65535, `APP_ENV` is dev/test/prod, `LOG_LEVEL` is a real level.
How secrets are protected: the API key, database password and optional `DATABASE_URL` are `SecretStr`, so they
print as `**********` everywhere; error messages never contain the secret (`hide_input_in_errors`).
Database URL: `URL.create(...)` keeps user, password, host and database as separate values, so characters like
`@ : / ? # %` and spaces in a password are escaped correctly. `safe_database_url` shows `***` instead of the password.
What `logging_config.py` does: one stderr handler, format `time LEVEL logger message`. You can pass known secrets;
any appearance in a message, its arguments or a traceback is replaced by `***`. SQLAlchemy's own SQL logging is
forced to WARNING so SQL parameters never reach the logs. Calling it twice does not duplicate lines.
Tests: `docker compose run --rm --no-deps backend pytest -q` -> 52 passed. `conftest.py` always replaces the API key with a
random fake one, so tests never use the real key.
Known limit: `ValidationError.errors()` (not `str()`) still contains the raw input; the app never logs it.
Common errors: `ValidationError ... ingest_api_key` = key missing/weak in `.env`; `ModuleNotFoundError: app` when running
pytest outside `backend/` (run it from there or in the container).
