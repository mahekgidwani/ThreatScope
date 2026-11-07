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

### Final independent review and fix pass (done)
An independent reviewer (a fresh agent that had never seen the code) read the whole branch (9 commits), re-ran the suite
(575 passed) and probed the live stack read-only. Verdict: "merge after fixes"; none of the five Review Focus items failed.
Fixed (one pass, tests written first - 87 new tests failed before the fix, all pass after; suite 575 -> 685):
1. **Lookalike domains were merged into the real domain.** Python's built-in `idna` codec (IDNA 2003) silently deleted or folded
   characters: `pay<soft hyphen>pal.com` became `paypal.com`, `faß.de` became `fass.de`, fullwidth digits `１２７.0.0.1` slipped through
   the "no IP in a domain" rule. Now the strict IDNA 2008 `idna` package is used (added to `requirements.txt`) with no silent
   mapping: invisible/zero-width characters, Roman-numeral and fullwidth lookalikes, dot lookalikes (`。`) and bad punycode are
   rejected with 422; `ß` stays distinct (`xn--fa-hia.de`); real international names still work (`пример.рф`).
2. **NUL characters caused a 500 on PostgreSQL.** PostgreSQL cannot store NUL in text/JSONB, SQLite can, so the tests could not
   see it. NUL (and lone surrogates) in `description`, in any metadata key/value, and in the `event_type` / indicator `value`
   filters are now a 422 / `invalid_filter`. Other control characters (newline, tab) are still allowed and round-trip.
3. **Huge `offset` (over 2^63-1) caused a 500.** Now a 422; the largest valid offset (2^63-1) returns an empty page.
4. **Timestamps whose UTC value falls before year 1 or after year 9999** (for example `0001-01-01T00:00:00+05:30`) caused a 500 on
   POST and on the time filters. Now a 422; the earliest/latest representable timestamps are accepted and round-trip.
5. **IPv6 scope IDs** (`fe80::1%eth0`) were accepted, split one address into several indicators and, when long, overflowed
   `varchar(45)` -> 500. Now rejected in the schema and the filter (shared `canonical_ip` helper).
6. **SQL parameters appeared in error logs** (event description/metadata of a failed insert). Engines now use `hide_parameters=True`.
Corrected in the docs only: the claim "no query strings in logs" (uvicorn's own access line still prints them) and
`RISK_SCORING.md` ("earlier" means stored earlier, not earlier `occurred_at`).
Deferred minors (not fixed on purpose): list filters `start_time`/`end_time` still accept Unix numbers (ingestion refuses
them); the indicator `value` filter is not normalised like the event `domain` filter (filter by the stored punycode/canonical
form); a request body is parsed before the API-key check and there is no body-size cap (localhost only); uvicorn's access
log prints query strings (`--no-access-log` would silence it).
Not changed (reviewer's question): `POSTGRES_PASSWORD` may still be `change-me`; the spec only requires placeholder rejection for
the API key and the database is bound to localhost.
Live proof after the fix (rebuilt image, backend restarted, database untouched): all 15 attack inputs returned 422 (none 500),
the rejected POSTs stored nothing (events total still 2), and the backend log held no server errors.

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
`METHOD /path STATUS duration` - no query string, headers or body. (Correction after the final review: uvicorn's own,
separate access-log line still prints the query string. No secret is sent in a query string by design, so the risk is low;
switching it off with `--no-access-log` is listed under deferred minors.) At startup the app loads the settings (a missing, weak or
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

## Phase 3 - Integrations and event collection
Branch `phase3/integrations`. Rule for every adapter: Source -> Adapter -> ThreatScope API -> Validation ->
Indicator extraction -> Risk scoring -> PostgreSQL. Adapters never touch the database.

### Task 1 - Shared integration foundation (done)
Files: `backend/integrations/{__init__,config,client}.py`, `backend/tests/integrations/`, `httpx` moved from
`requirements-dev.txt` to `requirements.txt` (adapters need it at run time; it was already installed in the image).
What: `ThreatScopeClient.submit_event(dict)` sends `POST /api/v1/events` with the `X-API-Key` header and returns
`SubmitResult(event_id, created)`. HTTP 409 `duplicate_event` is a normal result (`created=False`, existing id), not an
error. Everything else raises a subclass of `IntegrationError` with `.retryable`: connection/timeout/5xx = retryable;
401/403 (`ApiAuthError`), other 4xx (`ApiRejectedError`, includes field paths and messages from the API) and
unusable answers (`ApiResponseError`) = not retryable. The client never retries by itself; each adapter decides.
`stable_event_id(prefix, *parts)` builds a repeatable `external_event_id` (`prefix:` + 32 hex of SHA-256) so reading
the same log line / scanning the same file twice is rejected by the API's unique key instead of stored twice.
Settings (`IntegrationSettings`): `INGEST_API_KEY` (required, same variable as the API), `THREATSCOPE_API_URL`
(default `http://127.0.0.1:8000`; scheme://host:port only, no credentials/path/query), `THREATSCOPE_TIMEOUT_SECONDS`
(default 10, max 120). No database variables are needed.
Safety: the key is a `SecretStr`, only goes into the request header, is scrubbed from server-supplied error text,
and is never logged; redirects are not followed (the key would travel with them); proxy environment variables are
ignored (`trust_env=False`). The client does not duplicate validation: the API validates, and its 422 details are surfaced.
Tests: 58 new. Fake-server tests (MockTransport and real sockets for refused connection and silent server),
and contract tests against the REAL app on SQLite and PostgreSQL. Mutation check: removing the key scrub, enabling
redirects and breaking the duplicate branch made 6 tests fail; restored.
Common errors: `ApiAuthError` = wrong `INGEST_API_KEY`; `ApiConnectionError` = API not running or wrong URL.

### Task 2 - In-house static file analyser (done)
Files: `backend/integrations/file_formats.py` (PDF, DOCX/zip, PNG, JPEG parsers), `file_analyser.py` (limits, streamed
SHA-256, type detection, text/JSON/CSV, indicators, event builder), `analyse_file.py` (command line), and tests
`backend/tests/integrations/test_file_*.py` + `samples.py` (harmless sample builders). No new dependency: only the Python
standard library (`hashlib`, `zipfile`, `struct`, `re`, `json`, `csv`) plus the API's own `normalise_domain`. A PDF/Office
library (pypdf, python-docx, Pillow, python-magic) was judged not worth the install weight and attack surface for an MVP.
Use (no public upload endpoint; this is a local command):
`docker compose exec backend python -m integrations.analyse_file /path/in/container [--dry-run] [--max-bytes N]`.
To analyse a host file: `docker compose run --rm -v "F:\folder:/samples:ro" -e THREATSCOPE_API_URL=http://backend:8000 backend
python -m integrations.analyse_file /samples/file.pdf`. `--dry-run` prints the event and needs no API key.
What it records (event `source=file`, `event_type=file_analysis`): SHA-256 as `file_hash`, size, detected type (from
CONTENT, not the extension; a mismatch is a finding), structure (PDF version/encrypted flag, DOCX macro/embedded/external
parts, PNG/JPEG dimensions, JSON top-level kind, CSV rows/columns, line count), and IPv4s / domains / URLs found inside.
Never recorded: file contents. URLs are stored without credentials, query string or fragment.
Findings vs verdict: severity is `info`, or `low` when "review markers" exist (PDF JavaScript/OpenAction/Launch/embedded
file, DOCX macro project/embedded objects/remote template, data after PNG end, executable header, extension mismatch).
Other findings (unsupported format, malformed, truncated scan, invalid JSON/CSV) are notes only. Every event carries the
note "static analysis only ... not a malware verdict". Nothing is ever executed, opened in an application, or rendered.
Safety limits: files over 10 MB are refused; only the first 1 MB is parsed (the hash covers everything and `truncated` is
set); zip parts are read up to 2 MB and at most 5000 entries (a 60 MB zip bomb is never expanded: tested by peak memory);
PNG/JPEG are walked by seeking with bounded loops; indicator lists are capped (30 URLs, 50 IPs, 50 domains), so an event
always fits the API's metadata limit. Empty/missing/non-regular/unreadable files raise a clear error, not a crash.
Duplicates: `external_event_id = file:<first 32 hex of the SHA-256>`, so the same content is stored once whatever its name
(the API answers 409, the tool says "already recorded").
Why indicators sit in `metadata`: the API makes indicator rows only from top-level fields, so a file event has exactly one
indicator (`sha256`). Extra events per URL would inflate the hash's sighting count and the repeat-risk bonus. Phase 4
correlation can decide how to use the embedded values.
Known limits: no IPv6, no OCR/image content, no decompression of PDF streams (markers hidden in compressed streams or
obfuscated names are missed: "no markers" never means "safe"); bare domains only for a fixed list of common TLDs (URL hosts
always count), so rare TLDs and names like `self.info` can be wrong; UTF-16 text is treated as unknown binary; old
`.doc`/`.xls` and `.docm` are not parsed (a `.docm` shows as a plain zip/docx with a macro marker).
Tests: 110 new (full suite 853: 650 without PostgreSQL, 203 PostgreSQL-only). Mutation checks: removing the URL
sanitising, size limit, zip read cap and PNG trailing-data check each made tests fail (the zip-cap one only after adding a
peak-memory assertion). Dev database untouched (only `--dry-run` was used against it).

### Task 3 - openSquat domain adapter (done)
Files: `backend/integrations/opensquat_detector.py` (adapted detection + event builder), `opensquat_adapter.py`
(command line), `cli_common.py` (shared "build a client from the environment" helper; `analyse_file.py` now uses it too),
tests `test_opensquat_{detector,event,cli}.py` + `fakes.py`, `requirements.txt` (+ confusable_homoglyphs, homoglyphs),
`third_party/NOTICE.md` (openSquat attribution, modification list, dependency licences).
What openSquat gave us: the Levenshtein distance, the homograph check/conversion and the decision order (similarity ->
homograph -> "keyword inside the domain"). Its `SquattingDetector.check()` cannot be called as-is for structured results: it
only prints coloured text and returns domain names, so the kind and distance exist only inside the printed line. The adapter
therefore re-uses the functions and decision logic (GPL-3.0, header kept, changes listed) and returns `Finding` objects.
Biggest finding: openSquat's feed stores internationalised names as punycode (391 `xn--` lines in the 100k-line sample), and
its homograph check returns False for punycode, so the original would miss every IDN homograph in its own feed. We decode
first (tested: `xn--pypal-4ve.com` -> `domain_homograph`, distance 0 to "paypal").
Use: `docker compose exec backend python -m integrations.opensquat_adapter --keywords brands.txt --domains feed.txt
[--trusted own-domains.txt] [--confidence 0-4] [--max-events N] [--dry-run]` (files must be readable inside the container;
see Task 2 for `docker compose run -v` or `docker compose cp`). `--confidence` is openSquat's scale (default 1 = distance <= 1).
Event: `source=domain`, `domain` = punycode form, `event_type` = `domain_similarity` | `domain_homograph` |
`domain_keyword_match`; severity by distance (0-1 medium, 2 low, 3-4 info, keyword-contained low) and NEVER above medium;
description and metadata say "detection finding only, not a confirmed threat", `metadata.verified=false`; metadata also holds
keyword, detection kind, distance, confidence label, compared label and the Unicode form of the domain.
`external_event_id = domain:<hash(keyword, domain)>`: re-running over the same feed gives duplicates (counted, not errors);
one domain matching two keywords is two events, which raises that domain's sighting count (and the repeat-risk bonus).
Safety: feed read line by line (a 5 MB line is skipped unread); invalid lines are counted, not fatal; at most 500 findings per
run by default (`--max-events`); the run stops at once on a rejected key or an unreachable API; nothing touches the network
except the ThreatScope API.
Real-feed check (dry run, dev database untouched): 100,000 domains x 5 keywords in 11 s -> 21 findings (16 keyword-contained,
5 one-edit typos). It also shows why a finding is not a verdict: `amazoniagroup.com.br` contains "amazon".
Limits: only the first label is compared for similarity (like openSquat); the keyword fallback uses the whole name; no
legitimate-domain list except the optional `--trusted`; short or generic keywords are noisy; no DNS/web/certificate checks, so
nothing can say a domain is actually used for abuse.
Tests: 101 new (full suite 954: 747 without PostgreSQL, 207 PostgreSQL-only). Mutation checks: skipping the punycode decode,
ignoring the trusted list, dropping the keyword from the event id and removing the lower-casing each made tests fail.
