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
