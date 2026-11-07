# ThreatScope — Phase 1 Audit Report

Status: DRAFT for review. Nothing was installed, executed, deleted or modified during this audit.
Method: read-only inspection of folders, READMEs, requirements, Dockerfiles, compose files and selected source.
Anything marked **[UNTESTED]** was read in code/docs but not run. Anything marked **[UNVERIFIED]** could not be confirmed from local files.

---

## A. Repository Audit Report

### A.0 What is actually on disk

| # | Reference in brief | Local path | Found? |
|---|---|---|---|
| 1 | openSquat | `F:\Project codes\opensquat-master` | Yes (v2.3.0) |
| 2 | OWASP Python Honeypot (`OWASP/Python-Honeypot`) | — | **NOT FOUND** anywhere on F: |
| 3 | OWASP Honeypot-Project (`owasp/honeypot-project`) | `F:\Honeypot-Project` (+ `honeytraps\`) | Yes |
| 4 | FAME | `F:\fame` | Yes |

Important corrections to the brief:

- **Reference 2 is missing.** What is in `F:\Honeypot-Project` is reference 3 (ModSecurity/Apache/ELK/MISP honeytraps). It is a *different* project from OWASP Python Honeypot (which is a Python/Docker multi-protocol honeypot). They are not interchangeable.
- `F:\Project codes\opensquat-master` contains a **nested duplicate** `opensquat-master\opensquat-master` and a `.venv`. Only the outer copy is used as reference.
- `F:\Honeypot-Project` also holds `Gautam-Honeypot-Demo`, `Kartik-Honeypot`, `Nagarajan-Honeypot` (README-only or small `waf_modsec` copy) and `CHAMELEON-REN` (layered controller/WAF/personas/telemetry, has its own compose + Terraform). These look like contributor/side projects; **[UNVERIFIED]** whether they are part of upstream. Ignore for MVP.
- `.gitmodules` in Honeypot-Project is empty, so the `--recurse-submodules` in its README pulls nothing extra here.
- `F:\ThreaScope` is empty except `.claude`. It is not a git repository.

### A.1 openSquat

| Item | Finding |
|---|---|
| Purpose | Detect typosquatting, IDN homograph and phishing-style lookalike domains against a keyword (brand) list |
| Language / version | Python, `requires-python >=3.10`; classifiers list 3.10–3.12. Host has 3.13.0 → **[UNTESTED]** |
| Entry points | `opensquat.py` (CLI) and `opensquat.cli:main` (console script `opensquat`) |
| Core class | `opensquat/app.py: Domain.main(keywords_file, confidence_level, domains_file, dns, ...)` returns `list_domains` (list of domain strings) |
| Pure detection logic | `opensquat/squatting_detector.py: SquattingDetector.check(keyword, domains_list, result_buffer)` returns list of matching domain strings. Uses `validations.levenshtein`, `homograph.check_homograph/homograph_to_latin` |
| Input | Text file of keywords, text file of newly registered domains (NRD feed, downloaded from `feeds.opensquat.com`), optional DNS check, optional Premium API |
| Output | Console text (captured in `io.StringIO` buffers), plus TXT / JSON / CSV via `output.py: SaveFile` |
| Database | **None.** File in, file out |
| Dependencies | confusable_homoglyphs, homoglyphs, colorama, requests, beautifulsoup4, dnspython, urllib3, soupsieve |
| Docker | None provided |
| Licence | **GPL-3.0** (`LICENSE`, `pyproject.toml`) |
| Network behaviour | Downloads NRD feed from the internet; optional DNS lookups; optional VirusTotal / Premium API using keys |
| Concurrency | `ProcessPoolExecutor` per keyword → on Windows uses `spawn`; code must be import-safe and called under `if __name__ == "__main__"` **[UNTESTED]** |

Notes:
- Output is mixed into stdout with colour codes; a library-style call needs the buffer text discarded or the detector called directly.
- The files `api_key.txt` (801 bytes) and `vt_key.txt` (143 bytes) exist in the reference folder. **Contents were deliberately not read.** They are likely real credentials. They must never be copied into ThreatScope or committed.

### A.2 OWASP Honeypot-Project (`honeytraps`)

| Item | Finding |
|---|---|
| Purpose | ModSecurity (WAF) + Apache honeypot that plants "honeytraps"; logs attacks; ships logs to ELK; pushes events to MISP |
| Language | Mostly config (Apache, ModSecurity CRS rules), shell, Docker, a few Python scripts (`persona_watchdog.py`, `rule_watcher.py`, `misp-push`, `threat_intel/exporters`) |
| Entry points | `honeytraps/waf_modsec/docker-compose.yml` (honeypot), `honeytraps/waf_elk/docker-compose.yml` (ELK), `honeytraps/misp/run_misp.sh` (MISP) |
| Honeytraps | Fake listen ports (8000/8080/8888), fake `robots.txt` entry, fake HTML comments, fake hidden form fields, fake cookies (rules in `waf_modsec/modsecurity-extension.conf`) |
| Input | Any HTTP request to the container (honeypot port 9091 per README) |
| Output | ModSecurity JSON audit log (`SecAuditLogFormat JSON`) → Filebeat → Logstash → "v1.1 schema" JSON. Example event: `threat_intel/sample_event.json`, schema: `docs/v1.1_schema.json`, mapping: `docs/SCHEMA_MIGRATION.md` |
| Event fields useful to us | `event_type`, `event_envelope.timestamp`, `transaction.remote_address` (attacker IP), `transaction.local_address`, `request.request_line`, `attack_classification.{type,severity,honeytrap_triggered,honeytrap_rule_id,cve_triggered}`, `mitre_attack[]`, `geoip2.*` |
| Database | None itself. Uses Elasticsearch (ELK) and MISP (MySQL/MariaDB inside its containers) |
| Resource needs | README: ≥ 8 GB RAM, `vm.max_map_count ≥ 262144` for Elasticsearch, three containers (WAF, ELK, MISP) |
| Dependencies | `requirements.txt`: only `shodan>=1.31.0` (for `persona_watchdog.py`) |
| Licence | **No LICENSE file found** in `F:\Honeypot-Project` and no licence text in its READMEs → **[UNVERIFIED]**. Check the upstream GitHub repo licence before reuse and attribute OWASP. |

Notes:
- The honeypot is a **web-application (HTTP) honeypot**, not an SSH/FTP/telnet honeypot.
- ELK and MISP are heavy and not needed to demo ThreatScope. Our central PostgreSQL replaces ELK's storage role (per brief rule: no duplicate databases for the new app).

### A.3 FAME

| Item | Finding |
|---|---|
| Purpose | "FAME Automates Malware Evaluation": submit a file, run analysis modules, extract IOCs and malware family/config |
| Stack | Flask web app (`webserver.py`), Celery worker (`worker.py`, `celeryconfig.py`), **MongoDB** (pymongo) |
| Docker | `docker/docker-compose.yml` runs 4 services: `fame_web` (127.0.0.1:4200), `fame_worker`, `fame_updater`, `fame_db` (`mongo:latest`). Base image `debian:latest` |
| Dependencies | Flask, Werkzeug, celery, pymongo, python-magic, requests, Flask-Login, GitPython, ldap3, gunicorn, Sphinx, etc. |
| Analysis modules | `fame/modules/` is **empty** (only `__init__.py`). FAME downloads modules from separate git repositories at runtime. Out of the box it analyses nothing |
| Input | Web UI upload, or REST API: `AnalysesView.post` (`web/views/analyses.py:281`, uses `X-API-KEY`), file lookup by hash `/files/sha256/<sha256>` (`web/views/files.py:209`) |
| Output | Analysis documents in MongoDB; extracted observables/IOCs exposed in UI/API (`/analyses/<id>/refresh-iocs`) |
| Database | **MongoDB, deeply embedded** (`common/mongo_dict.py`, `core/*`). Porting to PostgreSQL is not feasible in 7 days |
| Licence | **GPL-3.0** |
| Config | `docker/fame.env` contains keys for MongoDB user/password and `DEFAULT_EMAIL` / `DEFAULT_PASSWORD`. Values were not inspected; treat as default credentials that must be changed |

Notes:
- `fame_worker` runs `privileged: true` with Docker-in-Docker so modules can launch containers. This is a major host-security concern.
- `docker-compose.yml` hardcodes `MONGO_INITDB_ROOT_PASSWORD: NeedToBeChanged`.

---

## B. Reusability Matrix

Legend: High = adapt directly; Med = adapt with work; Low = skip for MVP.

| Component | Source | Reuse | How we use it | Effort |
|---|---|---|---|---|
| Levenshtein / contains matching | openSquat `validations.py`, `squatting_detector.py` | **High** | Import `SquattingDetector.check()` (or re-implement the same algorithm) behind `domain_adapter`, one event per match | S |
| Homograph detection | openSquat `homograph.py` | **High** | Same adapter; flag `idn_homograph` in metadata | S |
| NRD feed download | openSquat `feed_manager.py` | Med | Needs internet; also offer a local sample feed file for offline demo | S |
| DNS validation | openSquat `dns_validator.py` | Med | Optional enrichment (is domain live) | S |
| CLI / console output / SaveFile | openSquat `cli.py`, `output.py` | Low | Not needed; our API replaces them | — |
| Premium API client / VT | openSquat `api_client.py`, `vt.py` | Low | Needs paid/personal keys; skip | — |
| ModSecurity honeytrap rules | Honeypot-Project `waf_modsec/modsecurity-extension.conf`, `httpd.conf`, `Dockerfile` | **High** | Run the existing `waf_modsec` container in Docker as our web honeypot | M |
| v1.1 event schema | Honeypot-Project `docs/v1.1_schema.json`, `sample_event.json` | **High** | Direct mapping source for `honeypot_adapter` (exact fields above) | S |
| Audit-log JSON → event | Honeypot-Project `waf_modsec/example-log.json` + schema | **High** | Our adapter tails the JSON audit log and maps to common event; no Logstash needed | M |
| ELK stack | `waf_elk/` | Low | Replaced by PostgreSQL + Streamlit | — |
| MISP push | `misp`, `misp-push` | Low | Heavy; mention as future work | — |
| Persona rotation | `personas/`, `persona_watchdog.py` | Low | Needs Shodan key; skip | — |
| FAME full stack | `F:\fame` | Low/Med | Heavy (4 containers, Mongo, privileged worker, no modules). Optional isolated stretch goal via REST API | L |
| FAME concepts (file hash, type via magic, IOC extraction, submission quota) | `fame/core/file.py`, `fame/common/utils.py` **[not yet read in depth]** | Med | Inspect before Phase 3; re-implement lightweight static analysis in our own `file_adapter` | M |
| OWASP Python Honeypot | missing | n/a | Cannot assess. Need repo or decision to drop | — |

Reuse decision (recommendation):
1. **openSquat** → import-level reuse (small, pure Python, no DB).
2. **Honeypot-Project** → container reuse (`waf_modsec`) + schema reuse; skip ELK/MISP.
3. **FAME** → do **not** embed. Build a lightweight static file analyser ourselves, inspired by FAME's workflow; keep an optional adapter that talks to a separately-run FAME over REST if time remains.

---

## C. Dependency Compatibility Report

Host (read-only checks): Python **3.13.0**, Docker **29.8.2**, `psql` **not installed**.
Python packages present now: sqlalchemy, streamlit, pydantic. Not present: fastapi, psycopg2, apscheduler, pytest, python-magic. (Versions not checked.)

| Concern | Detail | Risk | Mitigation |
|---|---|---|---|
| Python 3.13 vs openSquat | Declared support up to 3.12; `homoglyphs`, `confusable_homoglyphs` are old packages | Med **[UNTESTED]** | Pin ThreatScope to Python 3.12 in Docker (`python:3.12-slim`); test openSquat deps inside it |
| Python 3.13 vs FAME | Requirements are very new (`setuptools>=82`, `celery>=5.6`), Debian-based image | Low if run in its own container | Never import FAME into ThreatScope's venv |
| `requests` | openSquat `>=2.33.0`, FAME `>=2.34.2` | Low (compatible) | One venv for ThreatScope is fine; FAME stays in its container |
| `urllib3`, `soupsieve` pins | openSquat pins newer versions via Snyk comments | Low | Let pip resolve |
| Database mismatch | FAME = MongoDB; Honeypot = ELK/MISP; openSquat = none | **High** | Central PostgreSQL only for ThreatScope; FAME/Mongo isolated and polled; ELK/MISP dropped |
| `python-magic` | Needs `libmagic`; painful on Windows | Med | Run file analysis in Linux container (`libmagic1`) or use `filetype` lib / manual magic bytes |
| `ProcessPoolExecutor` on Windows | spawn start method | Low-Med | Run detection inside Docker (Linux fork) or guard with `__main__` |
| ELK memory | ≥ 8 GB RAM, `vm.max_map_count` | Med | Drop ELK |
| Flask vs FastAPI | Only inside FAME | None | No overlap if isolated |
| Licence mixing | openSquat GPL-3.0, FAME GPL-3.0, Honeypot-Project licence unknown | Med | See D.7 |
| Zeek | No native Windows support **[UNVERIFIED]**; Docker Desktop (WSL2) cannot sniff the host NIC easily | Med-High | Use Zeek in Docker on a sample `.pcap` → `conn.log`/`dns.log` as JSON; fallback: lightweight Python sensor |

---

## D. Proposed Integration Architecture

### D.1 Principle
Every source gets its own adapter that converts source output to one **common event**. Adapters only produce events; the backend does everything else.

```
 +-----------------+   +------------------+   +---------------+   +----------------+
 | domain_adapter  |   | honeypot_adapter |   | file_adapter  |   | network_adapter|
 | (openSquat code)|   | (tails ModSec    |   | (static       |   | (Zeek logs or  |
 |                 |   |  JSON audit log) |   |  analysis)    |   |  pcap parser)  |
 +--------+--------+   +---------+--------+   +-------+-------+   +--------+-------+
          \                      |                    |                    /
           \---------------------+----------+---------+-------------------/
                                             |  POST /api/v1/events (Pydantic validated)
                                    +--------v---------+
                                    |   FastAPI backend|
                                    | normalise -> store -> extract IOCs
                                    | -> correlate -> score -> incident
                                    +--------+---------+
                                             | SQLAlchemy
                                    +--------v---------+
                                    |   PostgreSQL     |
                                    +--------+---------+
                                             | REST
                                    +--------v---------+
                                    | Streamlit        |
                                    | dashboard        |
                                    +------------------+
 APScheduler (inside backend): domain scans, honeypot log tail, network log poll, correlation job.
 Honeypot container (Docker, isolated network) -> writes audit log to a shared volume.
```

### D.2 Proposed project layout (Phase 2 will create it)
```
ThreaScope/
  docker-compose.yml        # postgres, backend, dashboard, honeypot (isolated net)
  .env.example              # no real secrets
  backend/app/{main.py, config.py, db.py, models/, schemas/, api/, services/}
  adapters/{base.py, domain/, honeypot/, file/, network/}
  dashboard/app.py
  tests/
  docs/{PHASE1_AUDIT.md, DEVLOG.md}
  third_party/NOTICE.md     # attributions
```

### D.3 Common event (Pydantic `EventIn`)
`event_id` (UUID), `source` (`domain|honeypot|file|network`), `event_type`, `timestamp` (UTC), `src_ip`, `dst_ip`, `domain`, `url`, `file_hash`, `severity` (`info|low|medium|high|critical`), `description`, `metadata` (free JSON).

### D.4 Field mapping from references (verified from files)
| Common field | openSquat | Honeypot v1.1 | File analysis (ours) |
|---|---|---|---|
| source | `domain` | `honeypot` | `file` |
| event_type | `typosquat_match` / `homograph_match` | `attack_classification.type` (XSS, SQLi, …) | `file_analysed` |
| timestamp | scan time | `event_envelope.timestamp` | analysis time |
| src_ip | — | `transaction.remote_address` | — |
| dst_ip | — | `transaction.local_address` | — |
| domain | matched domain | Host header | extracted IOC |
| url | — | `request.request_line` | extracted IOC |
| file_hash | — | — | SHA-256 |
| severity | by confidence level | `attack_classification.severity` | by score |
| metadata | keyword, distance | `mitre_attack`, `geoip2`, `honeytrap_rule_id`, `cve_triggered` | type, entropy, size |

### D.5 Isolation rules
- Honeypot runs only in Docker on a dedicated network, bound to localhost (or a lab VLAN). Never port-forwarded for the demo.
- Uploaded files are stored, hashed and statically inspected only. **Never executed.** Validation: size cap, extension/magic check, random storage name, no path from user input.
- FAME (if used) stays in its own compose project, with changed default passwords. Its privileged worker is **not** enabled on the host unless approved.
- All secrets via `.env` (git-ignored).

### D.6 Zeek assessment
Feasible only as "Zeek in Docker reading a pcap, emitting JSON logs, adapter ingests `conn.log`/`dns.log`". Live capture on Windows is unreliable. Recommend: **MVP uses sample pcap + Zeek container if it runs within day 4; otherwise a small Python log/pcap parser.** Decision gate at end of Phase 3 day.

### D.7 Licensing and attribution (not legal advice)
- openSquat and FAME are GPL-3.0. Copying or adapting their code into ThreatScope makes that code (and the combined work, when distributed) GPL-3.0. For a college project this is fine, but we must: keep copyright headers, add `third_party/NOTICE.md`, and license ThreatScope as GPL-3.0-compatible.
- Calling FAME over REST or running the honeypot as a separate container keeps a clearer separation.
- Honeypot-Project licence: check upstream before reuse.

---

## E. Recommended PostgreSQL Design

One database `threatscope`, one schema. JSONB for source-specific data so adapters do not require migrations.

| Table | Key columns |
|---|---|
| `sources` | `id`, `name` (domain/honeypot/file/network), `enabled`, `last_run_at`, `last_status` |
| `events` | `id` UUID PK, `source_id` FK, `event_type`, `occurred_at` timestamptz, `received_at`, `src_ip` inet, `dst_ip` inet, `domain` text, `url` text, `file_hash` char(64), `severity` smallint/enum, `risk_score` int, `description`, `metadata` JSONB, `raw_hash` (dedupe) |
| `indicators` | `id`, `type` (ip/domain/url/sha256), `value`, `first_seen`, `last_seen`, `sighting_count`, `reputation_score`; UNIQUE(`type`,`value`) |
| `event_indicators` | `event_id` FK, `indicator_id` FK (many-to-many) |
| `incidents` | `id`, `title`, `status` (open/investigating/closed), `severity`, `risk_score`, `created_at`, `updated_at`, `summary` |
| `incident_events` | `incident_id` FK, `event_id` FK |
| `incident_notes` | `id`, `incident_id`, `author`, `note`, `created_at` |
| `scoring_rules` | `id`, `name`, `condition` JSONB, `points`, `enabled` |
| `file_analyses` | `id`, `event_id`, `sha256`, `md5`, `size`, `mime`, `entropy`, `stored_path`, `verdict`, `findings` JSONB |
| `domain_findings` | `id`, `event_id`, `keyword`, `matched_domain`, `technique` (levenshtein/homograph/contains), `distance`, `is_live` |

Indexes: `events(occurred_at)`, `events(source_id, event_type)`, `events(src_ip)`, `events(domain)`, `events(file_hash)`, `indicators(type,value)` unique, GIN on `events.metadata`.

Correlation (MVP, rule-based): an incident is opened or extended when ≥ 2 events share an `indicator` within a time window, or one event reaches a critical score. Risk score = sum of `scoring_rules` points + per-sighting bonus, capped at 100.

FAME's MongoDB and ELK are **not** merged into this. If FAME is used, a poller copies only its summary (hash, verdict, IOCs) into `events`/`file_analyses`.

---

## F. Seven-Day Risk Assessment

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | OWASP Python Honeypot missing | Certain | Med | Decide: obtain repo, or document that Honeypot-Project covers the honeypot role |
| 2 | FAME too heavy / no modules / MongoDB | High | High | Own lightweight file analyser; FAME optional |
| 3 | ELK + MISP RAM needs | High | Med | Drop both |
| 4 | Python 3.13 vs openSquat deps | Med | Med | Python 3.12 Docker image |
| 5 | Honeypot Docker build fails (old CRS/Apache base, Windows line endings) | Med | High | Build on day 2 as early smoke test; fallback: Python mock honeypot emitting the same v1.1 event |
| 6 | Zeek on Windows | High | Med | pcap replay in Docker, or Python fallback |
| 7 | GPL / unknown licence | Med | Low-Med | NOTICE file, attribute, check upstream |
| 8 | Secrets in reference folders (`api_key.txt`, `vt_key.txt`, `fame.env`) | Med | High | Never copy; `.gitignore`; rotate keys if they were ever shared |
| 9 | Scope creep (dashboard polish, extra sources) | High | Med | Freeze MVP: 4 adapters, 1 correlation rule set, 1 dashboard |
| 10 | Unable to demo offline | Med | Med | Local sample NRD feed, sample pcap, sample malware-like test file (EICAR) |
| 11 | Viva understanding gaps | Med | High | DEVLOG with "what / why / how" per module |

Overall: achievable if FAME is reduced to a lightweight analyser and ELK/MISP are dropped.

---

## G. Exact Next Tasks for Phase 2 (after your approval)

1. Create repo skeleton and `.env.example`, `.gitignore` (excluding any `*key*.txt`), `docker-compose.yml` with PostgreSQL only; `git init`.
2. Start PostgreSQL in Docker; verify with a connection test.
3. Pin Python 3.12 in a backend Dockerfile; add `requirements.txt` (fastapi, uvicorn, sqlalchemy, psycopg2-binary or psycopg, pydantic, alembic, apscheduler, pytest, httpx).
4. Define SQLAlchemy models for tables in section E and an Alembic initial migration.
5. Define Pydantic schemas (`EventIn`, `EventOut`, `IncidentOut`).
6. Implement endpoints: `GET /health`, `POST /api/v1/events`, `GET /api/v1/events`, `GET /api/v1/indicators`, `GET /api/v1/incidents`.
7. Pytest: schema validation test, event insert/read test against a test DB.
8. Write `README.md` and `docs/DEVLOG.md` entry for Phase 2.
9. Smoke test the Honeypot-Project `waf_modsec` Docker build (read its README first, ask before running).
10. Quick test of openSquat `SquattingDetector.check()` inside the Python 3.12 container with a tiny local keyword/domain list.

## Decisions needed from you
1. Python Honeypot repo: provide the local path or approve using Honeypot-Project (ModSecurity) as the only honeypot.
2. FAME: approve lightweight in-house file analyser as the MVP (FAME optional stretch).
3. Approve dropping ELK and MISP.
4. Licence: confirm ThreatScope may be GPL-3.0.
5. Approve moving to Phase 2.
