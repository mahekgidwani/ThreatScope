# ThreatScope — Phase 2 Design: Backend, Database, Common Event Model

Date: 2026-11-07 · Status: v2 (user refinements incorporated) · Awaiting approval of the implementation plan
Project directory (verified): `F:\ThreaScope`. `F:\ThreatScope` does not exist. The folder spelling stays `ThreaScope`; the product name is "ThreatScope". Nothing is renamed.

## 1. Intent

ThreatScope is a college cybersecurity platform (viva-assessed) that collects security events from four kinds of sources and shows them in one place. Phase 2 builds only the **central backend**: FastAPI + PostgreSQL + common event model + ingestion/retrieval APIs + config, error handling, tests. No adapters, dashboard, correlation or incident generation (Phases 3–4).

Success criteria:
1. `docker compose up` starts PostgreSQL and the backend; `GET /health` reports API and PostgreSQL separately.
2. A valid event POSTed to `/api/v1/events` is stored, scored, indexed and retrievable; invalid or duplicate events are rejected with a clear error.
3. `pytest` passes on SQLite **and** on real PostgreSQL; a manual round-trip against the running stack succeeds. Claims in the README are backed by executed output.
4. Every file is explained in plain language in `docs/DEVLOG.md`.

## 2. Inherited decisions (Phase 1 review)
Honeypot = OWASP Honeypot-Project ModSecurity container only (adapter layer stays modular). File analysis = in-house static analyser (Phase 3, never executes uploads). ELK/MISP dropped. GPL-3.0 accepted; keep notices; never copy openSquat keys. Original repositories are never modified. Phase 3 does not start until Phase 2 is implemented **and tested**.

## 3. Scope
In: FastAPI app, env config, logging, uniform errors, PostgreSQL via Compose, SQLAlchemy 2.0 models, Pydantic v2 schemas, ingestion + retrieval APIs, indicator extraction, experimental risk score, health endpoint, pytest suites, README/DEVLOG/NOTICE/LICENSE, git repo.
Out (postponed): adapters, `scoring_rules` / `incident_notes` / `file_analyses` / `domain_findings` tables (their phases), Zeek, correlation, incident creation, dashboard, Alembic, batch ingestion, user accounts.

## 4. Architecture
```
 Phase 3 adapters --HTTP POST /api/v1/events (X-API-Key)--> backend (FastAPI, Python 3.12, Docker)
   api/      thin routers: parse, call service, shape response
   schemas/  Pydantic = API contract
   services/ business logic (event_service, indicator_extractor, risk_scoring)
   models/   SQLAlchemy tables
   db.py     engine, session dependency, naming convention, init_db(), check_db()
   config.py env-based Settings      errors.py exception -> JSON mapping
                         | SQLAlchemy 2.0 + psycopg 3
                  PostgreSQL 16 (one DB: threatscope)
```
Layering: routers never query the DB; services never import FastAPI. Test-only SQLite is never used by the running app, so the single-central-database rule holds.

## 5. Components

### 5.1 Layout
```
F:\ThreaScope\
  .gitignore  .env.example  .env(ignored)  docker-compose.yml  LICENSE  README.md
  third_party\NOTICE.md
  docs\{PHASE1_AUDIT.md, DEVLOG.md, RISK_SCORING.md, superpowers\{specs,plans}}
  backend\
    Dockerfile  requirements.txt  requirements-dev.txt  pytest.ini
    app\{__init__,main,config,db,enums,logging_config,errors}.py
    app\models\{__init__,types,event,indicator,incident}.py
    app\schemas\{__init__,common,event,indicator,incident,health}.py
    app\services\{__init__,event_service,indicator_service,incident_service,indicator_extractor,risk_scoring}.py
    app\api\{__init__,deps,health,events,indicators,incidents}.py
    tests\{conftest.py, unit\..., db\..., api\...}
```

### 5.2 Common event model

| Field (API) | Type / rules |
|---|---|
| `id` | UUID, **server-generated** (uuid4), primary key. Clients cannot supply it. |
| `external_event_id` | Optional str, 1–128 chars, `[A-Za-z0-9._:\-]`. Client's own ID for duplicate protection. |
| `source` | enum `domain\|honeypot\|file\|network` (required) |
| `event_type` | str 1–64, `[a-z0-9_.-]` (required) |
| `occurred_at` | **Original event time** (the common format's "Timestamp"). Timezone-aware required; naive rejected; any offset converted to UTC. |
| `received_at` | **Server-generated** UTC time of ingestion. Never accepted from clients. |
| `source_ip`, `destination_ip` | Optional IPv4/IPv6, validated and stored in `ipaddress` canonical text form |
| `domain` | Optional. Lower-cased, trailing dot stripped, Unicode converted to IDNA/punycode (`xn--`), ≤ 253 chars; invalid → 422 |
| `url` | Optional. Scheme http/https/ftp, ASCII only (clients percent-encode), ≤ 1024 chars |
| `file_hash` | Optional. 64 hex chars (SHA-256), lower-cased |
| `severity` | enum `info\|low\|medium\|high\|critical` (required). Analyst-facing label from the source. |
| `risk_score` | int 0–100, **server-computed**, separate from severity (§5.5). Clients cannot set it. |
| `risk_factors` | JSON list of `{rule, points}` explaining the score (server-set) |
| `description` | str 1–2000 (required) |
| `metadata` | JSON object, default `{}`, serialized ≤ `MAX_METADATA_BYTES` (default 65536) |

`EventIn` uses `extra="forbid"`: unknown or server-owned fields (`id`, `received_at`, `risk_score`) are rejected with 422, not silently ignored.

### 5.3 Database (five tables, created with `create_all`)

| Table | Columns | Constraints and indexes |
|---|---|---|
| `events` | `id` UUID PK, `external_event_id` null, `source`, `event_type`, `occurred_at` timestamptz, `received_at` timestamptz, `source_ip`, `destination_ip`, `domain`, `url`, `file_hash`, `severity`, `risk_score`, `risk_factors` JSON, `description`, `metadata` JSON(B) | **UNIQUE(`source`,`external_event_id`)** (NULLs allowed, so events without an external ID are never blocked); CHECK severity ∈ enum, source ∈ enum, 0 ≤ risk_score ≤ 100; indexes: `occurred_at`, (`source`,`event_type`), `severity`, `source_ip`, `domain` |
| `indicators` | `id` PK, `type` (`ip\|domain\|url\|sha256`), `value`, `first_seen`, `last_seen`, `sighting_count` | **UNIQUE(`type`,`value`)**; CHECK type ∈ enum, `sighting_count` ≥ 1 |
| `event_indicators` | `event_id` FK, `indicator_id` FK | **PK(`event_id`,`indicator_id`)** (no duplicate links); FKs ON DELETE CASCADE; index on `indicator_id` |
| `incidents` | `id` PK, `title`, `status` (`open\|investigating\|closed`), `severity`, `risk_score`, `created_at`, `updated_at`, `summary` | CHECK status/severity ∈ enum, 0 ≤ risk_score ≤ 100; index `status`. No rows until Phase 4 |
| `incident_events` | `incident_id` FK, `event_id` FK | **PK(`incident_id`,`event_id`)** (no duplicate links); FKs ON DELETE CASCADE; index on `event_id` |

Portable types on purpose: `Uuid`, `String`, `DateTime(timezone=True)`, `JSON().with_variant(JSONB, "postgresql")`; enums as `String` + CHECK (`native_enum=False`). IPs are text (validated), not PG `inet`.
Timestamps: stored UTC. SQLite drops tzinfo, so a `UtcDateTime` TypeDecorator re-attaches UTC on read; PostgreSQL returns aware values natively.
Dedupe rule: events with the same (`source`,`external_event_id`) are duplicates → 409 containing the existing event `id`. Events with no `external_event_id` are never treated as duplicates (documented limitation).

### 5.4 API

| Method & path | Behaviour | Codes |
|---|---|---|
| `GET /health` | See §5.7 | 200 ready · 503 not ready |
| `POST /api/v1/events` | Ingest one event (needs `X-API-Key`). Returns full `EventOut` | 201 · 401 · 409 duplicate · 422 |
| `GET /api/v1/events` | Paged list, newest first (`occurred_at` desc, `id` desc) | 200 · 422 |
| `GET /api/v1/events/{id}` | One event incl. its indicators | 200 · 404 · 422 bad UUID |
| `GET /api/v1/indicators` | Paged; filters `type`, `value` (exact) | 200 · 422 |
| `GET /api/v1/incidents` | Paged; filter `status` (empty until Phase 4) | 200 · 422 |

Event list query parameters: `source`, `event_type`, `severity`, `source_ip`, `domain`, `start_time`, `end_time`, `limit` (default 50, **max 100**, min 1), `offset` (default 0, ≥ 0). `start_time` is inclusive and `end_time` exclusive, both must be timezone-aware, `start_time > end_time` → 422. All filters are exact matches (no LIKE, so `%` and `_` are plain characters). `domain` filter is normalised the same way as ingest. Response: `{items, total, limit, offset}`.
Error body (all errors): `{"error":{"code","message","details"}}`.
Interactive docs at `/docs`.

### 5.5 Risk score (experimental, rule-based)
`risk_score` is an **experimental prioritisation aid for ordering events, not a probability of compromise and not a verdict**. It is separate from `severity` (which is the source's own label). Computed once at ingest by the pure function `compute_risk(severity, source, repeat_sightings) -> (score, factors)`:

| Rule | Points |
|---|---|
| Severity: info 0 · low 10 · medium 25 · high 40 · critical 55 | 0–55 |
| Source: honeypot +15 (unsolicited contact) · file +10 · domain +5 · network +5 | 5–15 |
| Repeat indicators: +5 per previous sighting of the most-seen indicator on this event, capped at +20 | 0–20 |
| Total clamped to 0–100 | max 90 in Phase 2 |

Weights are constants in `risk_scoring.py`, documented in `docs/RISK_SCORING.md`, returned as `risk_factors`, and are expected to change after Phase 4 correlation/tuning. Under concurrent ingestion the repeat bonus is best-effort.

### 5.6 Ingestion flow (`event_service.create_event`)
1. Pydantic validates/normalises. 2. Build `Event` (server `id`, `received_at`). 3. Derive indicators: `source_ip`; `domain`; `url` and the URL's host (if a hostname, as a domain indicator, collapsed with `domain` when equal); `file_hash`; `destination_ip` **only when source is `network`** (for honeypots it is our own address and would falsely correlate everything). 4. Upsert indicators: get-or-create inside a SAVEPOINT (retry select on `IntegrityError`), atomic SQL increment `sighting_count = sighting_count + 1`, update `last_seen`. 5. Compute risk score. 6. Insert event + links in **one transaction**; `IntegrityError` on (`source`,`external_event_id`) → rollback → `DuplicateEventError` (409). 7. Log one line: `id`, source, type, severity, risk_score (never metadata, headers or the key).

### 5.7 Health
`GET /health` always returns JSON:
```
{"status":"ready|not_ready",
 "api":{"status":"up"},
 "database":{"status":"up|down","latency_ms":1.2}}
```
`api` is `up` whenever the process answers. `database` runs `SELECT 1` with a short timeout. Overall `ready` only if both are up; otherwise HTTP 503 and `database.status:"down"`. No exception text, host names or credentials in the body (details only in logs).

### 5.8 API-key security
Write endpoints require `X-API-Key`. The key is read from env `INGEST_API_KEY` into a `SecretStr`, compared with `hmac.compare_digest`, never logged, never returned. The app **refuses to start** if the key is missing, shorter than 16 chars, or equals the placeholder `change-me` (also in tests, which set their own random key). `.env` is in `.gitignore` before the first commit; `.env.example` holds placeholders only; a pre-commit-time secret scan step is part of the plan. Read endpoints are open and the stack binds to `127.0.0.1` only (MVP limitation, documented).

### 5.9 Configuration
`APP_ENV` (`dev|test|prod`), `LOG_LEVEL`, `INGEST_API_KEY`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_HOST_PORT` (Compose host mapping), `MAX_METADATA_BYTES`. `DATABASE_URL` is built from `POSTGRES_*` with `sqlalchemy.engine.URL.create` (so special characters need no escaping) unless `DATABASE_URL` is given explicitly.

### 5.10 Migrations (documented limits, Alembic-ready)
`create_all` creates missing tables only. It cannot alter existing tables, keeps no history and cannot roll back; a model change on a populated dev DB needs `docker compose down -v` (deletes data, so ask first). To stay Alembic-ready: one `Base.metadata` with a **constraint naming convention**, all models imported via `app.models`, `init_db()` isolated in `db.py` so it can later be replaced by `alembic upgrade head`, and no raw DDL outside models.

### 5.11 Technology
Python 3.12 (Docker `python:3.12-slim`, non-root user), PostgreSQL 16, SQLAlchemy 2.0, `psycopg[binary]` 3, FastAPI, Uvicorn, Pydantic v2 + pydantic-settings, pytest, httpx. No Alembic, Celery or other frameworks.

## 6. Errors and logging
`AppError` subclasses (`DuplicateEventError` 409, `NotFoundError` 404, `AuthError` 401) → uniform body. `SQLAlchemyError` → logged with traceback, generic 503/500 body without SQL. Unknown exceptions → 500 generic. Stdlib logging, level from `LOG_LEVEL`; a request-log line contains method, path, status, duration only.

## 7. Testing
| Suite | Runs on | Covers |
|---|---|---|
| `tests/unit` | none | config, schema validation, indicator extraction, risk scoring |
| `tests/db` | SQLite **and** PostgreSQL (parametrised) | constraints (unique external id, unique indicator, duplicate link rejected, CHECKs), insertion, retrieval, filtering, relationships, cascade, tz round-trip |
| `tests/api` | SQLite (fast) **and** PostgreSQL | create/get/list/filter/paging, auth, duplicate, health, error shape |
| PostgreSQL-only | PostgreSQL (`@pytest.mark.postgres`) | concurrent duplicate `external_event_id` → exactly one 201, rest 409; concurrent same-indicator ingest → `sighting_count == N`; JSONB metadata round-trip |

PostgreSQL tests are **mandatory**: plain `pytest` runs them and **fails (never skips)** when PostgreSQL is unreachable. `pytest -m "not postgres"` is the quick loop. Tests use a separate database `<POSTGRES_DB>_test`, created by the fixture, never the dev database. Tests run inside the backend container (Python 3.12, same network as `db`).
Phase 2 is done only when: full suite output (SQLite + PostgreSQL) is reported, a manual `Invoke-RestMethod` round-trip against the running stack succeeds, and the secret scan is clean.

## 8. Risks
| Risk | Mitigation |
|---|---|
| Docker Desktop not running (currently the case) | Plan step 0 starts it and verifies `docker info` |
| SQLite/PostgreSQL drift | Parametrised suites + mandatory PG run |
| Secrets committed | `.gitignore` first, secret scan before every commit |
| `create_all` limits | §5.10 |
| Unicode/IDN domains from openSquat | IDNA normalisation + tests |
| Index size limit on long values | URL ≤ 1024 ASCII chars |

## 9. Changes from the Phase 1 audit
`sources` table removed; IPs stored as validated text; `scoring_rules`, `incident_notes`, `file_analyses`, `domain_findings` postponed; Alembic postponed (kept ready); ELK/MISP removed; `file_hash` event filter dropped in favour of the seven requested filters; client-supplied `event_id` replaced by server `id` + optional `external_event_id`.

## 10. Deliverables
1. Git repo + `.gitignore` + LICENSE + NOTICE. 2. Compose + Docker + env. 3. Config/logging/db/errors. 4. Models + schemas. 5. Services (extractor, scoring, event service). 6. Routers (events, indicators, incidents, health). 7. Tests (SQLite + PostgreSQL). 8. README, DEVLOG, RISK_SCORING. 9. Honest test report; stop for approval before Phase 3.
