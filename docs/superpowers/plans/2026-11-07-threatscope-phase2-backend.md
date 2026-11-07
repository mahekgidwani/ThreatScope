# ThreatScope Phase 2 Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the central ThreatScope backend: FastAPI + PostgreSQL + common event model + ingestion/retrieval APIs + health check + tests, in a git repo, with nothing committed that is secret.

**Architecture:** Layered Python package `app` (routers → services → models → PostgreSQL). All behaviour is test-first. Quick tests run on in-memory SQLite; mandatory tests run on real PostgreSQL 16 in Docker Compose. The backend runs and is tested inside a Python 3.12 container.

**Tech Stack:** Python 3.12, FastAPI, Uvicorn, SQLAlchemy 2.0, psycopg 3, Pydantic v2 + pydantic-settings, PostgreSQL 16, Docker Compose, pytest, httpx.

**Spec:** `docs/superpowers/specs/2026-11-07-threatscope-phase2-backend-design.md` (v2). Executors must read it; section numbers below (§) refer to it.

**Status:** Design v2 APPROVED. Execution method: **native** (one continuous session, then one independent review). Revision 2 of this plan adds three safeguards (risk-score repeat schedule, localhost-only publishing, database safety) and per-task Objective / Expected results / Git checkpoint / Completion criteria. No architectural change was needed; if a technical issue ever forces one, stop and ask first.

**Task template:** every task lists Objective, Files, Interfaces, numbered steps (commands and tests inline), then *Expected results*, *Git checkpoint* (the commit step) and *Completion criteria*. A task is not done until its completion criteria are shown with real output.

## Global Constraints

- Project directory is exactly `F:\ThreaScope` (verified; `F:\ThreatScope` does not exist). Never modify the reference repos under `F:\fame`, `F:\Honeypot-Project`, `F:\Project codes`.
- Python 3.12 in Docker (`python:3.12-slim`), non-root user; PostgreSQL 16 (`postgres:16`, Debian-based; ruling in Task 2: the `-alpine` image failed with `exec format error` because its base layer was corrupted locally by a disk-full event). Host Python is 3.13 and is **not** used for the app or tests.
- **Local-only (safeguard 2):** every published port is bound to `127.0.0.1` only (backend 8000, Postgres `${POSTGRES_HOST_PORT:-5432}`); never `0.0.0.0` in a `ports:` mapping, no port forwarding, no public exposure. Read endpoints stay unauthenticated for the local MVP; this limitation is documented in README and DEVLOG. (Uvicorn listening on `0.0.0.0` *inside* the container is fine because only the localhost mapping is published.) Verified by `docker compose port` and `Get-NetTCPConnection` in Tasks 2 and 10.
- Event list: `limit` default 50, min 1, **max 100**; `offset` ≥ 0; filters exactly: `source, event_type, severity, source_ip, domain, start_time, end_time`; order `occurred_at desc, id desc`; `start_time` inclusive, `end_time` exclusive; all exact match (no LIKE).
- `id` is server-generated UUID; `external_event_id` optional, UNIQUE(`source`,`external_event_id`); duplicates → 409.
- `occurred_at` (original) and `received_at` (server) are separate, timezone-aware, stored UTC. Naive datetimes rejected.
- `severity` ∈ `info|low|medium|high|critical`; `risk_score` int 0–100 is server-computed, separate from severity, documented as an *experimental prioritisation score* (§5.5). `EventIn` is `extra="forbid"`.
- URL: http/https/ftp, ASCII only, ≤ 1024 chars. Metadata ≤ `MAX_METADATA_BYTES` (65536). Domains → lowercase, no trailing dot, IDNA/punycode, ≤ 253.
- `X-API-Key` on write endpoints only; key from env `INGEST_API_KEY` (`SecretStr`, ≥ 16 chars, ≠ `change-me`), `hmac.compare_digest`, never logged or returned; `.env` git-ignored **before** the first commit.
- PostgreSQL tests are mandatory: they **fail, never skip**, when PostgreSQL is unreachable. They use database `<POSTGRES_DB>_test`, never the dev database.
- Only the five tables: `events, indicators, event_indicators, incidents, incident_events`. Created with `create_all`; Alembic-ready (naming convention, single metadata, isolated `init_db`).
- Commit message trailer on every commit: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- **Risk repeat bonus (safeguard 1):** the current event is never counted as a previous sighting. Schedule by number of *earlier* events that mentioned the most-seen indicator: 0 → +0, 1 → +5, 2 → +10, 3 → +15, 4 or more → +20 (cap). So first sighting = no bonus, second = +5, third = +10. Explicit unit tests in Tasks 6 and 7.
- **Database safety (safeguard 3):** development database (`POSTGRES_DB`) and test database (`<POSTGRES_DB>_test`) are separate; tests refuse to run destructive setup (`drop_all`, `CREATE DATABASE`) unless the target name ends in `_test` and differs from `POSTGRES_DB`. The executor must **never** run, without the user's explicit approval in the conversation: `docker compose down -v`, `docker volume rm|prune`, `docker system prune`, `DROP DATABASE|SCHEMA|TABLE`, `TRUNCATE`/`DELETE` on the dev database, deleting `pgdata`/volumes, `git reset --hard`, `git clean`, or deleting `.env`. `docker compose stop|start|restart` and `up -d` are non-destructive and allowed. If a schema change needs a dev-DB reset, stop and ask.
- No Phase 3 work (adapters, file/domain tables, correlation, dashboard).

## Review Focus

Failure modes the spec implies but a simple happy-path test would miss (each is pinned by a named test in the owning task):

1. Unicode / homograph domains from openSquat (`аpple.com` with a Cyrillic `а`) must become `xn--…` and the domain filter must normalise the same way. → Task 5, Task 7.
2. Two clients POST the same `external_event_id` at the same instant: exactly one 201, the rest 409, never a 500. → Task 7 (PostgreSQL).
3. Many events mention the same domain concurrently: `sighting_count` must equal the number of events (atomic increment, no lost updates). → Task 7 (PostgreSQL).
4. Timestamps: naive rejected, `+05:30` converted to UTC, `start_time` inclusive / `end_time` exclusive boundary, naive filter times rejected. → Task 5, Task 7, Task 8.
5. Hostile query input: `limit=101|0`, `offset=-1`, non-UUID id, and `%` / `_` in `domain` filter treated literally (not wildcards). → Task 7, Task 8.

## Directory structure (final)

```
F:\ThreaScope\
  .gitignore  .env.example  .env (ignored, generated locally)  docker-compose.yml
  LICENSE  README.md  third_party\NOTICE.md
  docs\{PHASE1_AUDIT.md, DEVLOG.md, RISK_SCORING.md, superpowers\{specs,plans}\...}
  backend\
    Dockerfile  requirements.txt  requirements-dev.txt  pytest.ini
    app\__init__.py  main.py  config.py  db.py  enums.py  errors.py  logging_config.py
    app\models\__init__.py  types.py  event.py  indicator.py  incident.py
    app\schemas\__init__.py  common.py  event.py  indicator.py  incident.py  health.py
    app\services\__init__.py  indicator_extractor.py  risk_scoring.py  event_service.py  indicator_service.py  incident_service.py
    app\api\__init__.py  deps.py  health.py  events.py  indicators.py  incidents.py
    tests\conftest.py  tests\db_guard.py
    tests\unit\{test_db_guard.py, test_config.py, test_event_schema.py, test_indicator_extractor.py, test_risk_scoring.py}
    tests\db\{test_constraints.py, test_event_service.py, test_concurrency_pg.py}
    tests\api\{test_events_api.py, test_read_api.py, test_health.py}
```
(`enums.py`, `models/types.py` and the extra `*_service.py` files are also reflected in spec §5.1.)

## Conventions for all tasks

- PowerShell, working directory `F:\ThreaScope`: `Set-Location F:\ThreaScope`.
- Run tests in the container: `docker compose run --rm backend pytest <args>` (starts `db` automatically). Quick loop: add `-m "not postgres"`.
- "Expected" outputs are what a passing run looks like; if reality differs, stop and report it. Never mark a step done on assumption.
- Helper used in several steps (paste once per PowerShell session):
  `function Get-EnvValue($n){ ((Get-Content .env | Where-Object { $_ -match "^$n=" }) -replace "^$n=",'') }`

---

### Task 1: Preflight, git repository and licence files

**Objective:** Confirm the environment, start Docker Desktop, and create a git repository whose first commit contains only docs, licence and notices, with `.env` already ignored.

**Files:**
- Create: `.gitignore`, `.env.example`, `LICENSE`, `README.md` (stub), `third_party/NOTICE.md`, `docs/DEVLOG.md` (stub)

**Interfaces:** Produces: a git repo whose first commit contains docs only and no secrets.

- [ ] **Step 1: Preflight checks (no changes yet)**
  ```powershell
  Set-Location F:\ThreaScope
  Test-Path F:\ThreatScope          # expected: False
  Test-Path F:\ThreaScope           # expected: True
  git config --global user.name; git config --global user.email   # expected: non-empty (already set: Mahek Gidwani)
  ```
- [ ] **Step 2: Start Docker Desktop and wait for the engine** (it is currently stopped)
  ```powershell
  Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
  do { Start-Sleep 5; docker info --format '{{.ServerVersion}}' 2>$null } until ($LASTEXITCODE -eq 0)
  ```
  Expected: prints a version such as `29.x.x`. If the exe path differs, ask the user to start Docker Desktop manually.
- [ ] **Step 3: Check ports are free:** `Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 5432,8000` → no output. If 5432 is taken, set `POSTGRES_HOST_PORT=5433` in `.env` in Task 2.
- [ ] **Step 4: Create `.gitignore` FIRST** with at least: `.env`, `.env.*` (but `!.env.example`), `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.venv/`, `venv/`, `*.log`, `uploads/`, `*key*.txt`, `*.pem`, `pgdata/`, `.idea/`, `.vscode/`.
- [ ] **Step 5: Create `.env.example`** with keys and **placeholder values only**: `APP_ENV=dev`, `LOG_LEVEL=INFO`, `INGEST_API_KEY=change-me`, `POSTGRES_USER=threatscope`, `POSTGRES_PASSWORD=change-me`, `POSTGRES_DB=threatscope`, `POSTGRES_HOST=db`, `POSTGRES_PORT=5432`, `POSTGRES_HOST_PORT=5432`, `MAX_METADATA_BYTES=65536`.
- [ ] **Step 6: Licence and notices.** `Copy-Item F:\fame\LICENSE LICENSE` (reads the reference; verifies it is the GPL-3.0 text: `Select-String -Path LICENSE -Pattern 'GNU GENERAL PUBLIC LICENSE','Version 3'`). `third_party/NOTICE.md` must state: ThreatScope is GPL-3.0; openSquat (Andre Tenreiro, GPL-3.0, https://github.com/atenreiro/opensquat) will be adapted in Phase 3 with modifications documented here and no API keys copied; OWASP Honeypot-Project (licence not yet verified upstream — to be confirmed before Phase 3 reuse); FAME is a design reference only, no code copied. Stub `README.md` (title, one-paragraph purpose, "see docs") and `docs/DEVLOG.md` (heading + Phase 2 entry skeleton).
- [ ] **Step 7: Check for an existing repository, then initialise and verify nothing secret is staged**
  ```powershell
  Test-Path .git                      # if True: do NOT run git init
  # If .git exists: inspect instead of reinitialising
  #   git status --short --branch ; git log --oneline -n 20 ; git remote -v ; git branch -a
  #   Report what is there to the user and continue only with their direction (never git reset/clean/re-init).
  # If .git does not exist:
  git init -b main
  git add .
  git status --short            # expected: only .gitignore, .env.example, LICENSE, README.md, third_party/, docs/ (no .env, no backend/)
  git diff --cached -U0 | Select-String -Pattern '[0-9a-f]{40,}'   # expected: no output
  ```
- [ ] **Step 8: Commit**
  `git commit -m "chore: initialise ThreatScope repo with docs, licence and notices" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"`
  Expected: `[main (root-commit) …] … files changed`.

**Expected results:** `Test-Path F:\ThreatScope` False; Docker prints a version; ports free; `git status --short` lists only `.gitignore`, `.env.example`, `LICENSE`, `README.md`, `third_party/`, `docs/`; both secret-scan commands print nothing.
**Git checkpoint 1:** Step 8 commit.
**Completion criteria:** one commit exists on `main`; `LICENSE` is GPL-3.0; `NOTICE.md` records openSquat (GPL-3.0, to be adapted with modifications documented, no keys copied), Honeypot-Project (licence unverified) and FAME (design reference only); no secret in the index.

---

### Task 2: Docker, dependencies and a working PostgreSQL

**Objective:** Containerise the backend, bring up PostgreSQL 16 with a healthcheck, generate local secrets safely, and prove the stack is published on localhost only.

**Files:**
- Create: `backend/Dockerfile`, `backend/requirements.txt`, `backend/requirements-dev.txt`, `backend/pytest.ini`, `docker-compose.yml`, local-only `.env`

**Interfaces:** Produces: service `db` (healthy PostgreSQL) and image `backend` that can run `pytest`. Compose project reads `.env` for `${POSTGRES_*}`.

- [ ] **Step 1: `backend/requirements.txt`** (compatible-release pins): `fastapi~=0.115`, `uvicorn[standard]~=0.32`, `SQLAlchemy~=2.0.36`, `psycopg[binary]~=3.2`, `pydantic~=2.10`, `pydantic-settings~=2.6`. **`requirements-dev.txt`**: `-r requirements.txt`, `pytest~=8.3`, `httpx~=0.27`. If pip cannot resolve a pin on Python 3.12, loosen only that minor version and note it in DEVLOG.
- [ ] **Step 2: `backend/Dockerfile`:** `FROM python:3.12-slim`; env `PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1`; create non-root user uid 10001; `WORKDIR /app`; copy and `pip install --no-cache-dir -r requirements-dev.txt` before copying the rest (layer caching); `USER appuser`; `CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]`.
- [ ] **Step 3: `backend/pytest.ini`:** `testpaths = tests`, `addopts = -ra --strict-markers`, markers: `postgres: needs a real PostgreSQL (mandatory, never skipped)`.
- [ ] **Step 4: `docker-compose.yml`:** services `db` (`postgres:16`, env from `${POSTGRES_USER|PASSWORD|DB}`, volume `pgdata`, port `127.0.0.1:${POSTGRES_HOST_PORT:-5432}:5432`, healthcheck `pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB` interval 5s retries 10) and `backend` (build `./backend`, `env_file: .env`, `environment: POSTGRES_HOST: db, POSTGRES_PORT: "5432"`, port `127.0.0.1:8000:8000`, volume `./backend:/app`, `depends_on: db: condition: service_healthy`, command `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`). No `privileged`, no Docker socket mount. Top-level `volumes: pgdata:`.
- [ ] **Step 5: Generate `.env` locally with random secrets, without printing them or writing a BOM**
  ```powershell
  function New-Hex($n){ $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') }) }
  $text = (Get-Content .env.example -Raw) -replace 'INGEST_API_KEY=change-me', "INGEST_API_KEY=$(New-Hex 24)" -replace 'POSTGRES_PASSWORD=change-me', "POSTGRES_PASSWORD=$(New-Hex 16)"
  [IO.File]::WriteAllText("$PWD\.env", $text, (New-Object Text.UTF8Encoding($false)))
  git check-ignore -v .env      # expected: prints the .gitignore rule that ignores .env
  git status --short            # expected: .env NOT listed
  ```
- [ ] **Step 6: Build the image and start only the database**
  ```powershell
  docker compose build backend      # expected: ends with "naming to docker.io/library/threascope-backend" (name may differ)
  docker compose up -d db
  docker compose ps                 # expected: db ... (healthy) within ~15 s
  docker compose port db 5432       # expected: 127.0.0.1:5432 (or your POSTGRES_HOST_PORT); 0.0.0.0 = STOP and fix the mapping
  ```
- [ ] **Step 7: Verify dependencies and DB access**
  ```powershell
  docker compose run --rm --no-deps backend python -c "import fastapi,sqlalchemy,psycopg,pydantic,pytest,httpx,sys;print(sys.version.split()[0],fastapi.__version__,sqlalchemy.__version__,pydantic.VERSION)"
  docker compose exec db psql -U (Get-EnvValue POSTGRES_USER) -d (Get-EnvValue POSTGRES_DB) -c "select version();"
  ```
  Expected: `3.12.x <versions>`; then a row starting `PostgreSQL 16`. Record the printed versions in DEVLOG.
- [ ] **Step 8: Commit** `backend/` + `docker-compose.yml` (confirm `.env` is not staged): `git add backend docker-compose.yml; git status --short; git commit -m "build: add Docker Compose, backend image and PostgreSQL service" -m "Co-Authored-By: …"`.

**Expected results:** image builds; `db` is `healthy`; Python `3.12.x` with fastapi/sqlalchemy/pydantic versions printed; `select version()` shows PostgreSQL 16; `docker compose port db 5432` shows `127.0.0.1:…`; `.env` ignored and not staged.
**Git checkpoint 2:** Step 8 commit.
**Completion criteria:** DB reachable from the backend container; versions recorded for DEVLOG; no `0.0.0.0` published mapping; no volume or data command was run.

---

### Task 3: Configuration and logging

**Objective:** Load all settings from environment variables, refuse weak or placeholder API keys, never expose secrets in output, and set up logging.

**Files:**
- Create: `backend/app/__init__.py`, `backend/app/config.py`, `backend/app/logging_config.py`, `backend/tests/conftest.py` (env bootstrap only for now), `backend/tests/unit/test_config.py`

**Interfaces:**
- Produces: `class Settings(BaseSettings)` with `app_env: Literal["dev","test","prod"]`, `log_level: str`, `ingest_api_key: SecretStr`, `postgres_user: str`, `postgres_password: SecretStr`, `postgres_db: str`, `postgres_host: str = "db"`, `postgres_port: int = 5432`, `max_metadata_bytes: int = 65536`, `database_url: str | None = None`, property `sqlalchemy_url -> sqlalchemy.engine.URL`; `get_settings() -> Settings` (`lru_cache`); `configure_logging(level: str) -> None`.
- `conftest.py` top-of-file (before any `app` import) sets `os.environ` defaults: `APP_ENV=test`, `INGEST_API_KEY=<secrets.token_hex(16)>` exposed as module constant `TEST_API_KEY`, and dummy `POSTGRES_*` only if unset.

- [ ] **Step 1: Write failing tests** in `tests/unit/test_config.py` (build with `Settings(_env_file=None, ingest_api_key=..., postgres_user=..., postgres_password=..., postgres_db=...)`):
  ```python
  def test_short_key_rejected():            with pytest.raises(ValidationError): make(ingest_api_key="short")
  def test_placeholder_key_rejected():      with pytest.raises(ValidationError): make(ingest_api_key="change-me")
  def test_missing_key_rejected(monkeypatch):  monkeypatch.delenv("INGEST_API_KEY"); with pytest.raises(ValidationError): Settings(_env_file=None, postgres_user="u", postgres_password="p", postgres_db="d")
  def test_secrets_never_in_repr():         s = make(ingest_api_key="k"*32, postgres_password="pw-SECRET"); assert "k"*32 not in repr(s) and "pw-SECRET" not in repr(s) and "pw-SECRET" not in str(s)
  def test_url_built_with_special_chars():  assert make(postgres_password="p@ss:/w?rd").sqlalchemy_url.password == "p@ss:/w?rd"
  def test_explicit_database_url_wins():    assert make(database_url="sqlite://").sqlalchemy_url.drivername == "sqlite"
  def test_defaults():                      assert make().max_metadata_bytes == 65536
  ```
- [ ] **Step 2: Run:** `docker compose run --rm backend pytest tests/unit/test_config.py -q` → Expected: FAIL (`ModuleNotFoundError: app.config`).
- [ ] **Step 3: Implement `Settings`/`get_settings`** (field validator on `ingest_api_key` enforcing ≥ 16 chars and ≠ `change-me`; URL via `URL.create("postgresql+psycopg", ...)`). **Implement `configure_logging`** (stdlib `logging.basicConfig`, format `%(asctime)s %(levelname)s %(name)s %(message)s`, invalid level → INFO).
- [ ] **Step 4: Run again** → Expected: `7 passed`.
- [ ] **Step 5: Commit** `feat: add environment-based settings with API-key validation and logging`.

**Expected results:** red run shows `ModuleNotFoundError`; green run `7 passed`.
**Git checkpoint 3:** Step 5 commit.
**Completion criteria:** all 7 config tests pass; no secret appears in `repr`/`str` of settings; weak/missing key makes `Settings()` raise.

---

### Task 4: Database layer, models and constraint tests

**Objective:** Build the SQLAlchemy layer and the five tables with their uniqueness, check and foreign-key constraints, plus the test fixtures that run every database test on SQLite and on real PostgreSQL, guarded so the dev database cannot be touched.

**Files:**
- Create: `backend/app/db.py`, `app/enums.py`, `app/models/{__init__,types,event,indicator,incident}.py`, `tests/db/test_constraints.py`, `tests/db_guard.py`, `tests/unit/test_db_guard.py`
- Modify: `tests/conftest.py` (database fixtures)

**Interfaces:**
- `enums.py`: `class Source(StrEnum)`: `domain, honeypot, file, network`; `Severity`: `info, low, medium, high, critical`; `IndicatorType`: `ip, domain, url, sha256`; `IncidentStatus`: `open, investigating, closed`.
- `db.py`: `NAMING_CONVENTION: dict`; `class Base(DeclarativeBase)` with `metadata = MetaData(naming_convention=NAMING_CONVENTION)`; `make_engine(url) -> Engine` (adds `connect_args={"connect_timeout": 2}` for PostgreSQL only, `pool_pre_ping=True`); `get_engine() -> Engine` (cached, from `get_settings().sqlalchemy_url`); `get_db() -> Iterator[Session]` (FastAPI dependency; commit is the caller's job, rollback on exception, always close); `init_db(engine: Engine) -> None` (`Base.metadata.create_all`, the only place DDL is issued); `check_db(engine: Engine) -> tuple[bool, float | None]` (ok, latency_ms; `SELECT 1`; never raises).
- `models/types.py`: `UtcDateTime(TypeDecorator)` (stores aware, returns aware UTC, rejects naive on bind), `JsonType = JSON().with_variant(JSONB, "postgresql")`.
- Models per spec §5.3 with exactly those columns, CHECK constraints (`String` + `CheckConstraint`, enum values listed), UNIQUE/PK/FK(`ondelete="CASCADE"`)/indexes. `Event.event_metadata` maps to DB column named `metadata`. Relationships: `Event.indicators: list[Indicator]` (via `event_indicators`), `Incident.events: list[Event]` (via `incident_events`). Association tables are `EventIndicator` and `IncidentEvent` classes with composite PKs. `app.models` exports all five plus `Base` usage so importing `app.models` registers every table.
- `conftest.py` produces: fixture `engine` parametrised `["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)]`; SQLite = in-memory `StaticPool` + `PRAGMA foreign_keys=ON` listener; PostgreSQL = ensure `<POSTGRES_DB>_test` exists (connect to maintenance DB `postgres` with `AUTOCOMMIT`, create if missing; on connection failure call `pytest.fail("PostgreSQL is mandatory …")`), then per test `drop_all` + `init_db` — **but only after** `assert_safe_test_database(url: URL, dev_db_name: str) -> None` (in `tests/db_guard.py`) has passed: it calls `pytest.fail` unless the database name ends with `_test` and differs from `dev_db_name`. The dev database is never opened by tests. Fixture `session(engine) -> Session`. Fixture `pg_engine` (PostgreSQL only, same creation logic).

- [ ] **Step 1: Write failing tests** `tests/db/test_constraints.py` (all use fixture `session`, helper `make_event(**kw) -> Event` with valid defaults):
  - `test_event_roundtrip_keeps_utc`: insert `occurred_at=datetime(2026,11,7,15,30,tzinfo=timezone(timedelta(hours=5,minutes=30)))`; reload; assert `.occurred_at.utcoffset() == timedelta(0)` and `.occurred_at == original` (same instant), `.received_at.tzinfo is not None`.
  - `test_unique_external_id_per_source`: same (`source`,`external_event_id`) → `IntegrityError`; same external id with another source → OK; two events with `external_event_id=None` → OK.
  - `test_check_constraints`: `severity="bogus"`, `source="bogus"`, `risk_score=101`, `risk_score=-1` each → `IntegrityError`.
  - `test_indicator_unique_and_count_check`: duplicate (`type`,`value`) → `IntegrityError`; `sighting_count=0` → `IntegrityError`.
  - `test_duplicate_event_indicator_link_rejected` and `test_duplicate_incident_event_link_rejected` → `IntegrityError`.
  - `test_incident_status_check`: `status="bogus"` → `IntegrityError`.
  - `test_relationship_navigation`: event linked to 2 indicators → `event.indicators` has both; incident linked to event → `incident.events == [event]`.
  - `test_cascade_delete_removes_links`: delete event → its `event_indicators` and `incident_events` rows gone, indicator and incident rows remain.
  - `test_init_db_is_idempotent`: calling `init_db(engine)` twice raises nothing.
  - `test_constraint_names_follow_convention`: unique constraint name on `events` equals `uq_events_source_external_event_id` (convention `uq_%(table_name)s_%(column_0_N_name)s`); this proves Alembic-readiness.
  - `@pytest.mark.postgres test_jsonb_metadata_roundtrip(pg_engine)`: nested dict/list/unicode metadata round-trips equal.
  - `tests/unit/test_db_guard.py`: `test_guard_refuses_dev_database` (name `threatscope` with dev name `threatscope` → fails), `test_guard_refuses_name_without_test_suffix` (`prod_db`), `test_guard_accepts_test_database` (`threatscope_test`), `test_guard_runs_before_any_drop_all` (the PostgreSQL fixture calls the guard first; assert via a stub URL that points at a non-`_test` name and expect `pytest.fail`/`Failed`, with no engine created).
- [ ] **Step 2: Run** `docker compose run --rm backend pytest tests/db/test_constraints.py -q` → Expected: FAIL (import errors).
- [ ] **Step 3: Implement** `enums.py`, `db.py`, `models/*`, fixtures. Use SQLAlchemy 2.0 `Mapped[...]`/`mapped_column`. Primary keys: `Event.id` is `Uuid` with `default=uuid.uuid4`; `Indicator.id` and `Incident.id` are autoincrement integers.
- [ ] **Step 4: Run** the same command → Expected: all pass for both `[sqlite]` and `[postgres]` ids.
- [ ] **Step 5: Verify tables exist in the dev database too** (after Task 8 `main` runs `init_db`; here just ensure the test DB exists): `docker compose exec db psql -U (Get-EnvValue POSTGRES_USER) -l` → lists `<db>_test`.
- [ ] **Step 6: Commit** `feat: add database layer, enums and five-table models with constraints`.

**Expected results:** red run fails on imports; green run shows every constraint test twice (`[sqlite]` and `[postgres]`), the JSONB test once, guard tests pass; `psql -l` lists `<db>_test` beside the dev DB.
**Git checkpoint 4:** Step 6 commit.
**Completion criteria:** all five tables created on both engines; each uniqueness, check, PK and cascade rule proven by a test on PostgreSQL; constraint names follow the naming convention; guard tests pass; the dev database was not modified by any test.

---

### Task 5: Pydantic schemas

**Objective:** Define the API contract (`EventIn`/`EventOut`, indicators, incidents, health, paging) with strict validation and normalisation of timestamps, IPs, domains, URLs, hashes and metadata.

**Files:**
- Create: `backend/app/schemas/{__init__,common,event,indicator,incident,health}.py`, `tests/unit/test_event_schema.py`

**Interfaces:**
- `common.py`: `class Page(BaseModel, Generic[T])`: `items: list[T]`, `total: int`, `limit: int`, `offset: int`; `class ErrorBody`.
- `event.py`: `EventIn` (`model_config = ConfigDict(extra="forbid")`; fields `external_event_id: str | None`, `source: Source`, `event_type: str`, `occurred_at: datetime`, `source_ip: str | None`, `destination_ip: str | None`, `domain: str | None`, `url: str | None`, `file_hash: str | None`, `severity: Severity`, `description: str`, `metadata: dict[str, Any] = {}`); `RiskFactor(rule: str, points: int)`; `EventOut` (`from_attributes=True`; `id: UUID`, `received_at`, `risk_score: int`, `risk_factors: list[RiskFactor]`, `indicators: list[IndicatorOut]`, plus all input fields; `metadata` populated from ORM attribute `event_metadata` via `validation_alias`). `normalise_domain(value: str) -> str` public helper (also used by the list filter in Task 7/8).
- `indicator.py`: `IndicatorOut(id: int, type: IndicatorType, value: str, first_seen, last_seen, sighting_count: int)`. `incident.py`: `IncidentOut`. `health.py`: `HealthOut` (§5.7 shape).

- [ ] **Step 1: Write failing tests** in `tests/unit/test_event_schema.py` with `BASE = dict(source="honeypot", event_type="xss_attempt", occurred_at="2026-11-07T10:00:00Z", severity="high", description="x")`:
  ```python
  def test_valid_minimal_event():              assert EventIn(**BASE).occurred_at.utcoffset() == timedelta(0)
  def test_naive_timestamp_rejected():         with pytest.raises(ValidationError): EventIn(**{**BASE, "occurred_at": "2026-11-07T10:00:00"})
  def test_offset_converted_to_utc():          e = EventIn(**{**BASE, "occurred_at": "2026-11-07T15:30:00+05:30"}); assert (e.occurred_at.hour, e.occurred_at.minute, e.occurred_at.utcoffset()) == (10, 0, timedelta(0))
  @pytest.mark.parametrize("f", ["id","received_at","risk_score","risk_factors"])
  def test_server_owned_fields_rejected(f):    with pytest.raises(ValidationError): EventIn(**{**BASE, f: 1})
  def test_unicode_domain_to_punycode():       assert EventIn(**BASE, domain="Bücher.Example.").domain == "xn--bcher-kva.example"
  def test_cyrillic_homograph_domain():        assert EventIn(**BASE, domain="\u0430pple.com").domain.startswith("xn--")
  @pytest.mark.parametrize("d", ["bad_domain!.com", "a"*64+".com", "", "-bad.com", "x"*250+".com"])
  def test_invalid_domain_rejected(d):         with pytest.raises(ValidationError): EventIn(**BASE, domain=d)
  def test_ip_canonical_and_invalid():         assert EventIn(**BASE, source_ip="2001:0DB8:0:0:0:0:0:1").source_ip == "2001:db8::1"; with pytest.raises(ValidationError): EventIn(**BASE, source_ip="999.1.1.1")
  @pytest.mark.parametrize("u", ["javascript:alert(1)", "http://exämple.com/", "http://" + "a"*1030 + ".com"])
  def test_url_rejected(u):                    ...ValidationError
  def test_url_ftp_allowed():                  EventIn(**BASE, url="ftp://files.example/x")
  def test_file_hash_lowercased_and_validated(): "AB"*32 -> lowercase; 63 chars, non-hex -> ValidationError
  def test_metadata_too_large_rejected():      EventIn(**BASE, metadata={"k": "x"*70000}) -> ValidationError
  def test_bad_event_type_and_external_id():   "Bad Type!" and external_event_id "has space" -> ValidationError
  def test_description_required_and_bounded(): "" and "x"*2001 -> ValidationError
  ```
- [ ] **Step 2: Run** `pytest tests/unit/test_event_schema.py -q` → FAIL (module missing).
- [ ] **Step 3: Implement schemas.** Domain: strip, lower, drop one trailing `.`, `encode("idna")` (failure → `ValueError`), then enforce ≤ 253 total and label regex `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$` per label. IPs: `str(ipaddress.ip_address(v))`. Datetime: reject when `tzinfo is None`, then `.astimezone(timezone.utc)`. Metadata size: `len(json.dumps(v, ensure_ascii=False).encode())` ≤ `get_settings().max_metadata_bytes`.
- [ ] **Step 4: Run again** → Expected: all pass.
- [ ] **Step 5: Commit** `feat: add Pydantic schemas with strict validation and normalisation`.

**Expected results:** red run `ModuleNotFoundError: app.schemas`; green run all schema tests pass, including the Cyrillic homograph, `+05:30` conversion and server-owned-field rejection cases.
**Git checkpoint 5:** Step 5 commit.
**Completion criteria:** invalid input is rejected with `ValidationError`; accepted input is normalised (UTC, canonical IP, punycode lowercase domain, lowercase hash); no server-owned field can be set by a client.

---

### Task 6: Indicator extractor and risk scoring (pure logic)

**Objective:** Implement the two pure functions that decide which indicators an event contributes and what experimental risk score it receives, with the first-sighting-gets-zero-bonus rule proven by explicit tests.

**Files:**
- Create: `backend/app/services/{__init__,indicator_extractor,risk_scoring}.py`, `tests/unit/test_indicator_extractor.py`, `tests/unit/test_risk_scoring.py`

**Interfaces:**
- Consumes: `EventIn`, `normalise_domain`, enums.
- Produces: `extract_indicators(ev: EventIn) -> list[tuple[IndicatorType, str]]` (ordered, de-duplicated, may be empty); `compute_risk(severity: Severity, source: Source, prior_sightings: int) -> tuple[int, list[dict]]` where each factor is `{"rule": str, "points": int}`; `prior_sightings` means **the number of earlier events that already mentioned the most-seen indicator of this event; the current event is NOT included** (negative values are treated as 0); constants `SEVERITY_POINTS`, `SOURCE_POINTS`, `REPEAT_POINTS_EACH = 5`, `REPEAT_CAP = 20` exposed at module level.

- [ ] **Step 1: Write failing tests**
  - Extractor (build events with a helper): honeypot with `source_ip` + `destination_ip` → only `[(ip, source_ip)]`; **network** event includes destination IP; same IP as source and destination (network) → one entry; `url="http://evil.example/a"` → `(url, …)` and `(domain, "evil.example")`; URL host equal to `domain` → single domain entry; `url="http://203.0.113.9/x"` → `(ip, "203.0.113.9")` and no domain entry; `file_hash` → `(sha256, hash)`; event with no indicator fields → `[]`.
  - Risk: `compute_risk(Severity.info, Source.domain, 0)[0] == 5`; `(critical, honeypot, 0)[0] == 70`; `(low, file, 1)[0] == 25`; `(low, file, 10)[0] == 40` (cap +20); parametrised `test_repeat_bonus_schedule` with `prior_sightings` 0,1,2,3,4,5,6 → repeat points exactly 0, 5, 10, 15, 20, 20, 20 (read the repeat points from the `repeat_indicator` factor, 0 when absent); `test_first_sighting_has_no_repeat_factor` (prior 0 → no `repeat_indicator` factor and total equals severity + source points only); `test_second_sighting_adds_5_third_adds_10`; for 20 sampled combinations `sum(f["points"] for f in factors) == score` and `0 <= score <= 100`; factor rule names are `severity:<name>`, `source:<name>`, `repeat_indicator` (last only when > 0); negative `prior_sightings` treated as 0.
- [ ] **Step 2: Run** both files → FAIL.
- [ ] **Step 3: Implement** both modules (weights exactly as spec §5.5: severity info 0, low 10, medium 25, high 40, critical 55; source honeypot 15, file 10, domain 5, network 5).
- [ ] **Step 4: Run** → all pass.
- [ ] **Step 5: Commit** `feat: add indicator extraction and experimental risk scoring`.

**Expected results:** red run fails on import; green run all extractor and risk tests pass (schedule 0/5/10/15/20/20/20 proven).
**Git checkpoint 6:** Step 5 commit.
**Completion criteria:** `destination_ip` is an indicator only for `network` events; repeated values inside one event collapse to one indicator; score always within 0–100 and equals the sum of its factors; first sighting has zero repeat bonus.

---

### Task 7: Services — create, get, list (SQLite and PostgreSQL)

**Objective:** Implement event creation (one transaction, atomic indicator counting, duplicate protection, risk scoring), single-event retrieval and filtered, paged listing, proven on SQLite and on real PostgreSQL including concurrency.

**Files:**
- Create: `backend/app/errors.py` (exceptions only for now), `app/services/{event_service,indicator_service,incident_service}.py`, `tests/db/test_event_service.py`, `tests/db/test_concurrency_pg.py`

**Interfaces:**
- `errors.py`: `class AppError(Exception)` with `status_code: int`, `code: str`, `message: str`, `details: dict`; `DuplicateEventError(existing_id: UUID)` (409, `duplicate_event`, details `{"existing_id": str}`); `NotFoundError(what: str)` (404, `not_found`); `AuthError()` (401, `unauthorized`).
- `event_service.py`: `create_event(db: Session, data: EventIn) -> Event` (flow §5.6; commits on success; rollback + `DuplicateEventError` on the unique violation, looking up the existing id); `get_event(db: Session, event_id: UUID) -> Event` (raises `NotFoundError`); `@dataclass EventFilters(source: Source|None, event_type: str|None, severity: Severity|None, source_ip: str|None, domain: str|None, start_time: datetime|None, end_time: datetime|None)`; `list_events(db: Session, f: EventFilters, limit: int, offset: int) -> tuple[list[Event], int]`.
- `indicator_service.py`: `list_indicators(db, type: IndicatorType|None, value: str|None, limit: int, offset: int) -> tuple[list[Indicator], int]`. `incident_service.py`: `list_incidents(db, status: IncidentStatus|None, limit: int, offset: int) -> tuple[list[Incident], int]`.

- [ ] **Step 1: Write failing tests** `tests/db/test_event_service.py` (fixture `session`, both backends):
  - `test_create_stores_event_indicators_and_risk`: honeypot event with `source_ip="203.0.113.42"` and `url="http://evil.example/a"` → event persisted with UUID `id`, aware `received_at` ≥ time before call, `risk_score == 55` when the event's severity is `high` (severity 40 + honeypot 15 + repeat 0; use `high`, not `critical`), `risk_factors` has `severity:high` and `source:honeypot` and no `repeat_indicator`, exactly 3 indicators linked (`ip`, `url`, `domain evil.example`), each `sighting_count == 1`.
  - `test_repeat_bonus_schedule_across_events`: create six events with the same `source_ip`, identical `severity` and `source`; `sighting_count` after each is 1..6; `risk_score` sequence is `base, base+5, base+10, base+15, base+20, base+20` (so the **first sighting gets no bonus** and the current event is never counted); the first event's `risk_factors` has no `repeat_indicator`.
  - `test_indicator_repeated_within_one_event_counts_once`: one event whose `domain` equals its URL host → that domain indicator has `sighting_count == 1` and the event gets no repeat bonus.
  - `test_occurred_at_and_received_at_are_independent`: `occurred_at` of 2020 preserved; `received_at` is "now".
  - `test_duplicate_external_id_raises_and_leaves_no_partial_rows`: second create with same (`source`,`external_event_id`) raises `DuplicateEventError` whose `existing_id` equals the first `id`; afterwards event count is 1 and the shared indicator's `sighting_count` is still 1.
  - `test_without_external_id_never_duplicate`: same payload twice, no external id → 2 events.
  - `test_get_event_and_not_found`: round trip incl. `.indicators`; random UUID → `NotFoundError`.
  - `test_list_filters` (one assertion per filter, 7 filters) and `test_filters_combine_with_and`.
  - `test_list_paging_and_order`: 5 events; `limit=2, offset=2` returns the 3rd–4th newest; `total == 5`; ordering `occurred_at` desc, ties by `id` desc.
  - `test_time_range_boundaries`: event exactly at `start_time` is included, exactly at `end_time` excluded.
  - `test_domain_filter_normalised`: ingest `Bücher.example`; filter with `BÜCHER.example` and with `xn--bcher-kva.example` both match; cyrillic-`а` homograph filter does not match the latin one.
  - `test_filter_wildcards_are_literal`: events with domains `a.example`, `b.example`; filter `domain="%"` and `"_.example"` → `total == 0`.
  - `test_list_indicators_and_incidents`: filter by `type`/`value`; incidents empty → `([], 0)`.
  `tests/db/test_concurrency_pg.py` (`pg_engine`, `@pytest.mark.postgres`, `ThreadPoolExecutor(8)`, each worker opens its own `Session`):
  - `test_concurrent_duplicate_external_id`: 8 workers create the same (`source`,`external_event_id`) → exactly 1 success, 7 `DuplicateEventError`, 0 other exceptions; 1 row.
  - `test_concurrent_same_indicator_sightings`: 8 workers each create a distinct event mentioning domain `shared.example` → 8 events and indicator `sighting_count == 8`.
- [ ] **Step 2: Run** both files → FAIL.
- [ ] **Step 3: Implement.** Indicator upsert = SELECT; if absent, INSERT inside `session.begin_nested()` and on `IntegrityError` re-SELECT; then `UPDATE indicators SET sighting_count = sighting_count + 1, last_seen = :now WHERE id = :id` (SQL expression, not read-modify-write). `prior_sightings` for scoring = highest `sighting_count` among this event's indicators **after** its own atomic increment, **minus 1**, so the current event is explicitly excluded (first sighting → 0). Event insert + link inserts + commit in one transaction; catch `IntegrityError` on flush/commit, `rollback()`, map to `DuplicateEventError` after re-querying the existing id. List: build a SQLAlchemy `select` with only parametrised equality filters; `total` from `select(func.count())` on the same filtered subquery.
- [ ] **Step 4: Run** → all pass on `[sqlite]` and `[postgres]`; concurrency tests pass on PostgreSQL.
- [ ] **Step 5: Commit** `feat: add event ingestion, retrieval and indicator services`.

**Expected results:** red run fails on import; green run passes every service test on `[sqlite]` and `[postgres]`; both concurrency tests pass on PostgreSQL (1 success + 7 `DuplicateEventError`; `sighting_count == 8`).
**Git checkpoint 7:** Step 5 commit.
**Completion criteria:** create/get/list behave as specified; duplicate leaves no partial rows; filters, paging, boundary and wildcard-literal tests pass; repeat bonus schedule proven end to end; no data command touched the dev database.

---

### Task 8: Errors, authentication, API routers and app factory

**Objective:** Expose the services as the REST API with API-key protection on writes, uniform JSON errors, strict query validation and a request logger that never records secrets.

**Files:**
- Modify: `backend/app/errors.py` (add `register_handlers`)
- Create: `backend/app/api/{__init__,deps,events,indicators,incidents}.py`, `backend/app/main.py`, `tests/api/test_events_api.py`, `tests/api/test_read_api.py`
- Modify: `tests/conftest.py` (client fixtures)

**Interfaces:**
- `errors.register_handlers(app: FastAPI) -> None`: handlers for `AppError` (→ `{"error":{"code","message","details"}}`), `RequestValidationError` (→ 422, code `validation_error`, details = list of `{loc,msg}` only, no input echo), `SQLAlchemyError` (log traceback; 503 `database_error`, generic message), `Exception` (500 `internal_error`, generic).
- `deps.py`: `require_api_key(x_api_key: str | None = Header(default=None)) -> None` raising `AuthError` (compare with `hmac.compare_digest` on UTF-8 bytes; never log header); `get_engine_dep() -> Engine` (returns `db.get_engine()`; overridable in tests).
- `main.py`: `create_app(run_startup: bool = True) -> FastAPI`; lifespan calls `configure_logging`, `init_db(get_engine())` only when `run_startup`; registers handlers and routers (`/health`, `/api/v1/events`, `/api/v1/indicators`, `/api/v1/incidents`); a middleware logging `method path status duration_ms` only; module-level `app = create_app()`.
- Routes: `POST /api/v1/events` (`dependencies=[Depends(require_api_key)]`, `status_code=201`, body `EventIn`, returns `EventOut`); `GET /api/v1/events` (query params per Global Constraints with `Query(ge=1, le=100)` for `limit`, `Query(ge=0)` for `offset`; naive or `start_time > end_time` → 422); `GET /api/v1/events/{event_id: UUID}`; `GET /api/v1/indicators`; `GET /api/v1/incidents`. List responses are `Page[...]`. The `domain` query value is passed through `normalise_domain`; invalid domain filter → 422.
- `conftest.py` produces: fixture `client(engine) -> TestClient` built with `create_app(run_startup=False)` and `dependency_overrides[get_db]` bound to the parametrised engine; constant `AUTH = {"X-API-Key": TEST_API_KEY}`; helper `payload(**over) -> dict`.

- [ ] **Step 1: Write failing tests**
  `test_events_api.py`:
  - `test_post_requires_api_key`: no header → 401, wrong key → 401, body `error.code == "unauthorized"`; response text never contains the real key.
  - `test_post_creates_event_201`: body has UUID `id`, `received_at`, `risk_score` int, `risk_factors`, `severity` unchanged, `indicators` list, and no key text.
  - `test_post_rejects_server_owned_fields`: payload with `id` / `risk_score` / `received_at` → 422 `validation_error`.
  - `test_post_duplicate_returns_409`: second POST same (`source`,`external_event_id`) → 409, `error.code == "duplicate_event"`, `details.existing_id` equals first id.
  - `test_422_shape_has_no_input_echo`: invalid IP → 422, `error.details[0]` has `loc` and `msg`, response does not contain the offending input string.
  - `test_key_not_logged` (uses `caplog` at DEBUG): after a POST, `TEST_API_KEY not in caplog.text`.
  - `test_post_unicode_domain_stored_as_punycode`.
  `test_read_api.py`:
  - `test_get_event_round_trip_and_404_and_bad_uuid` (200 / 404 `not_found` / 422 for `/api/v1/events/not-a-uuid`).
  - `test_reads_need_no_key`.
  - `test_list_defaults_and_paging`: default response `limit == 50`, `offset == 0`; `limit=2&offset=1` correct slice and `total`.
  - `test_limit_and_offset_bounds`: `limit=101` → 422, `limit=0` → 422, `limit=100` → 200, `offset=-1` → 422.
  - `test_each_filter_via_query_string` (all 7) and `test_start_after_end_422`, `test_naive_start_time_422`, `test_time_boundaries_inclusive_start_exclusive_end`.
  - `test_percent_in_domain_filter_is_literal` (`?domain=%25` → `total == 0`).
  - `test_indicators_endpoint_lists_and_filters` and `test_incidents_endpoint_empty_page` (`items == []`, `total == 0`, `?status=bogus` → 422).
- [ ] **Step 2: Run** `pytest tests/api/test_events_api.py tests/api/test_read_api.py -q` → FAIL.
- [ ] **Step 3: Implement** the files above; routers contain no queries. Use `Depends(get_db)`.
- [ ] **Step 4: Run** → all pass on both backends.
- [ ] **Step 5: Commit** `feat: add REST API for events, indicators and incidents with API-key auth`.

**Expected results:** red run fails on import; green run passes all API tests on both backends (401/201/409/422/404, paging bounds, filters, no key in responses or logs).
**Git checkpoint 8:** Step 5 commit.
**Completion criteria:** `limit` > 100 or < 1 and `offset` < 0 give 422; write endpoint rejects missing/wrong key; error bodies use the uniform shape without echoing input; read endpoints work without a key (documented local-MVP limitation).

---

### Task 9: Health endpoint

**Objective:** Provide `GET /health` that reports API availability and PostgreSQL connectivity separately with an overall readiness status, leaking no internals.

**Files:**
- Create: `backend/app/api/health.py`, `tests/api/test_health.py`
- Modify: `backend/app/main.py` only if the router is not yet registered

**Interfaces:** `GET /health` → `HealthOut`: `{"status": "ready"|"not_ready", "api": {"status": "up"}, "database": {"status": "up"|"down", "latency_ms": float | null}}`; HTTP 200 when ready else 503. Depends on `get_engine_dep` and `db.check_db`.

- [ ] **Step 1: Write failing tests**
  - `test_health_ready` (client on each backend, override `get_engine_dep` with the test engine): 200; `status == "ready"`; `api.status == "up"`; `database.status == "up"`; `isinstance(database.latency_ms, float)`.
  - `test_health_reports_db_down_separately`: override `get_engine_dep` with `make_engine("postgresql+psycopg://u:p@127.0.0.1:1/x")` → 503; `status == "not_ready"`; `api.status == "up"`; `database.status == "down"`; `database.latency_ms is None`; response text contains none of `psycopg`, `127.0.0.1`, `password`, `Traceback`.
  - `test_health_needs_no_key`.
- [ ] **Step 2: Run** `pytest tests/api/test_health.py -q` → FAIL.
- [ ] **Step 3: Implement** router: `ok, ms = check_db(engine)`; log the failure reason inside `check_db` (at WARNING, without credentials).
- [ ] **Step 4: Run** → all pass.
- [ ] **Step 5: Commit** `feat: add /health with separate API and PostgreSQL status`.

**Expected results:** red run fails (404 for `/health`); green run: ready case 200, database-down case 503 with `api: up`, `database: down`, no driver/host/password text.
**Git checkpoint 9:** Step 5 commit.
**Completion criteria:** the three health tests pass on the parametrised backends; `check_db` never raises.

---

### Task 10: Documentation, full verification and final commit

**Objective:** Document everything for the viva, run the complete verification (SQLite + PostgreSQL suites, live stack round trip, localhost-only proof, secret scan) and report the real results honestly.

**Files:**
- Create: `docs/RISK_SCORING.md`
- Modify: `README.md`, `docs/DEVLOG.md`, `third_party/NOTICE.md` (only if facts changed)

**Interfaces:** Produces the evidence required by the completion criteria below.

- [ ] **Step 1: `docs/RISK_SCORING.md`:** purpose ("experimental prioritisation score, not a probability or verdict"), weight tables from §5.5, worked examples (`high` honeypot, first sighting = 40 + 15 + 0 = 55; `critical` honeypot, first sighting = 55 + 15 + 0 = 70; second sighting of the same indicator adds +5), limits (best-effort under concurrency, weights to be tuned in Phase 4).
- [ ] **Step 2: `README.md`:** what it is; prerequisites (Docker Desktop, PowerShell); setup (copy `.env.example`, the secret-generation snippet from Task 2); run (`docker compose up -d --build`); URLs (`http://127.0.0.1:8000/docs`, `/health`); example `Invoke-RestMethod` POST and GET; test commands (full, quick `-m "not postgres"`); `create_all` limitations and Alembic path (§5.10); security notes (`.env` ignored, key handling, ports published on 127.0.0.1 only, **read endpoints are intentionally unauthenticated for the local MVP: never expose the API publicly, forward the port or change the binding**, no TLS); common errors table (Docker engine not running → start Docker Desktop; port in use → change `POSTGRES_HOST_PORT`; `ValidationError: ingest_api_key` → set a ≥ 16-char key in `.env`; `password authentication failed` after changing `.env` → volume keeps the old password; resetting needs `docker compose down -v`, which deletes all data and must **never be run without the user's explicit approval**; 401 → header `X-API-Key`; 409 → duplicate `external_event_id`).
- [ ] **Step 3: `docs/DEVLOG.md` Phase 2 entry:** for every file created: what it is, why, how it works, how to run/test it, expected result, common errors (viva-oriented, plain language); resolved dependency versions from Task 2; any deviation from this plan.
- [ ] **Step 4: Full automated verification**
  ```powershell
  docker compose run --rm backend pytest -q                  # everything: SQLite + PostgreSQL
  docker compose run --rm backend pytest -q -m "not postgres"   # quick loop still green
  docker compose run --rm backend pytest -q -m postgres      # PostgreSQL-only set
  ```
  Expected: `N passed` with `0 failed`, `0 errors`, no skips for `postgres`-marked tests. Paste the three summary lines into DEVLOG. Also prove the "fail, don't skip" rule once: `docker compose stop db; docker compose run --rm --no-deps backend pytest -q -m postgres` → **FAILED** with the "PostgreSQL is mandatory" message; then `docker compose up -d db`.
- [ ] **Step 5: Start the real stack and do a manual round trip**
  ```powershell
  docker compose up -d --build
  docker compose ps                                  # db healthy, backend running
  docker compose port backend 8000                   # expected: 127.0.0.1:8000
  docker compose port db 5432                        # expected: 127.0.0.1:5432
  Get-NetTCPConnection -State Listen -LocalPort 8000,5432 | Select-Object LocalAddress,LocalPort   # expected: LocalAddress 127.0.0.1 only; any other address = STOP and report
  Invoke-RestMethod http://127.0.0.1:8000/health     # expected: status ready, api up, database up
  $h = @{ "X-API-Key" = (Get-EnvValue INGEST_API_KEY) }
  $body = @{ source="honeypot"; external_event_id="demo-001"; event_type="xss_attempt"; occurred_at="2026-11-07T10:00:00+05:30"; source_ip="203.0.113.42"; url="http://evil.example/a?q=1"; severity="high"; description="Demo XSS probe"; metadata=@{rule="9500001"} } | ConvertTo-Json
  $r = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/events -Headers $h -ContentType "application/json" -Body $body
  $r | Select-Object id,received_at,occurred_at,severity,risk_score   # expected: UUID, occurred_at 04:30Z, high, risk_score 55 (40 high + 15 honeypot + 0 first sighting)
  Invoke-RestMethod "http://127.0.0.1:8000/api/v1/events/$($r.id)"
  (Invoke-RestMethod "http://127.0.0.1:8000/api/v1/events?source=honeypot&limit=10").total   # expected: 1
  try { Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/events -Headers $h -ContentType "application/json" -Body $body } catch { $_.Exception.Response.StatusCode.value__ }   # expected: 409
  try { Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/events -ContentType "application/json" -Body $body } catch { $_.Exception.Response.StatusCode.value__ }   # expected: 401
  docker compose exec db psql -U (Get-EnvValue POSTGRES_USER) -d (Get-EnvValue POSTGRES_DB) -c "\dt"   # expected: the five tables
  docker compose exec db psql -U (Get-EnvValue POSTGRES_USER) -d (Get-EnvValue POSTGRES_DB) -c "select type,value,sighting_count from indicators;"  # expected: ip, url, domain rows with count 1
  docker compose stop db
  try { Invoke-RestMethod http://127.0.0.1:8000/health } catch { $_.Exception.Response.StatusCode.value__; (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() }   # expected: 503 and a body with status not_ready, api up, database down
  docker compose start db
  ```
  Paste the observed outputs into DEVLOG (replace any expected value that differs, and say so).
- [ ] **Step 6: Secret scan before the final commit**
  ```powershell
  git status --short                              # .env must not appear
  git check-ignore -v .env                        # prints the ignoring rule
  git add -A
  git diff --cached --name-only | Select-String -Pattern '(^|/)\.env$','key.*\.txt$','\.pem$'   # expected: no output
  git diff --cached -U0 | Select-String -Pattern '[0-9a-f]{32,}'                              # expected: no output (or only non-secret hashes in tests/docs – inspect each hit)
  $k = Get-EnvValue INGEST_API_KEY; $p = Get-EnvValue POSTGRES_PASSWORD
  git grep --cached -n -F -e $k -e $p             # expected: no output
  ```
- [ ] **Step 7: Git checkpoint 10, then report** `git commit -m "docs: add README, development log and risk-scoring notes; Phase 2 verified" -m "Co-Authored-By: …"`; then report the actual test and round-trip results to the user and **stop**. Do not start Phase 3.

**Expected results:** full suite `N passed, 0 failed, 0 errors`; PostgreSQL-only run passes; with `db` stopped the PostgreSQL tests FAIL with the mandatory-PostgreSQL message; round trip prints 201 data (risk_score 55 on first sighting of a `high` honeypot event), total 1, then 409 and 401; `\dt` lists exactly the five tables; ports show `127.0.0.1`; secret scan prints nothing.
**Git checkpoint 10:** Step 7 commit.
**Completion criteria:** see the project-level list below; additionally the final report states every command run and every result, including anything that deviated from "expected".

---

## Completion criteria (all must be true, with output shown to the user)

1. `git log --oneline` shows the task commits; `git status` clean; `.env` ignored and absent from history (`git log --all --stat -- .env` empty).
2. `docker compose run --rm backend pytest -q` passes completely, including every `postgres`-marked test; stopping PostgreSQL makes those tests fail, not skip.
3. `GET /health` returns `ready` with API and database reported separately, and `not_ready` (503) with database `down` when PostgreSQL is stopped.
4. Manual round trip: create 201 → get → list/filter → duplicate 409 → no key 401; `\dt` shows exactly the five tables.
5. Unique and PK constraints verified by tests on PostgreSQL (duplicate external id, duplicate indicator, duplicate event-indicator link, duplicate incident-event link).
6. README, DEVLOG (each file explained), RISK_SCORING and NOTICE are present and match what was actually run.
7. Safeguards shown with evidence: (1) repeat-bonus schedule 0/5/10/15/20/20 passes in Tasks 6 and 7; (2) `docker compose port` and `Get-NetTCPConnection` show `127.0.0.1` only, and the unauthenticated-read limitation is in README and DEVLOG; (3) the db-guard tests pass, tests used only `<db>_test`, and no destructive command (`down -v`, volume removal, `DROP`, `TRUNCATE`/`DELETE` on dev, `git reset --hard`) was run without explicit approval.
8. User reviews results and approves before any Phase 3 work.
