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
