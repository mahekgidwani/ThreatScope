# ThreatScope Phase 3: integrations and event collection

Phase 3 turns ThreatScope from a backend that *accepts* security events into a platform that *collects* them.
Three source adapters are built and tested end to end. Network monitoring is **deferred** (section 9).

```
Source -> Adapter -> ThreatScope API -> Validation -> Indicator extraction -> Risk scoring -> PostgreSQL
```

## 1. What exists

| Source | Adapter command (run inside the backend container) | Reads | Event types | Reference project |
|---|---|---|---|---|
| `file` | `python -m integrations.analyse_file PATH... [--dry-run] [--max-bytes N]` | files you name (never executed) | `file_analysis` | none (own code; FAME was rejected in Phase 1) |
| `domain` | `python -m integrations.opensquat_adapter (--keyword W \| --keywords F) --domains FEED [--trusted F] [--confidence 0-4] [--max-events N] [--dry-run]` | keyword list + one-domain-per-line feed | `domain_similarity`, `domain_homograph`, `domain_keyword_match` | openSquat 2.3.0 (GPL-3.0, adapted) |
| `honeypot` | `python -m integrations.modsec_adapter LOG [--state F] [--max-events N] [--dry-run]` | ModSecurity JSON audit log (read-only) | `xss_attempt`, `sqli_attempt`, `rce_attempt`, `lfi_attempt`, `rfi_attempt`, `php_injection_attempt`, `scanner_probe`, `protocol_anomaly`, `waf_alert`, ... | OWASP Honeypot-Project (log format only; no code used) |
| `network` | not built | | | Zeek evaluated, deferred (`docs/NETWORK_DECISION.md`) |

Every adapter prints a plain summary, exits `0` (all good), `1` (some events failed) or `2` (bad usage or configuration), and
supports `--dry-run` (print the events, send nothing, no API key needed).

## 2. Architecture rules (and how they are enforced)

1. **Adapters never write to PostgreSQL.** Each one builds an event and calls the API. Validation, indicator extraction,
   risk scoring and storage happen once, in the Phase 2 backend. *Enforced by* `tests/integrations/test_architecture.py`
   (no database library or backend service is imported anywhere in `backend/integrations/`; only the shared validators
   `app.schemas.event` and the logging setup `app.logging_config` are imported from `app`).
2. **One client, one endpoint.** Only `integrations/client.py` touches the network, and it calls only `POST /api/v1/events`.
3. **Nothing is executed.** No `subprocess`, `eval`, `exec`, dynamic imports or pickle in the adapters (same test).
4. **Secrets stay secret.** The API key is a `SecretStr`, goes only into a request header, is scrubbed from server-supplied
   error text, and never appears in output, logs, state files or stored events (end-to-end test reads the server log).
5. **Findings are not verdicts.** File events are `info` or `low`; openSquat events never above `medium`; honeypot events
   follow the WAF's own severity (CRS attack rules map to `high` at most; only a ModSecurity ALERT/EMERGENCY would give
   `critical`). Every event says it is a detection or static-analysis result.
6. **Idempotent.** Each event has a stable `external_event_id` (hash of what identifies it at its source), so re-running an
   adapter over the same input stores nothing twice (the API answers 409 and the adapter reports "already recorded").
7. **Phase 2 was untouched in Phase 3.** `backend/app/` had no change on the Phase 3 branch (checked with `git diff main..HEAD`; Phases 4 and 5 changed it later, see the DEVLOG). Phase 3 added
   `backend/integrations/`, tests, docs, and three dependencies (`httpx` moved to runtime, `confusable_homoglyphs`, `homoglyphs`).

## 3. Configuration

Adapters read the same `.env` / environment as the API:

| Variable | Default | Meaning |
|---|---|---|
| `INGEST_API_KEY` | (required for real submission) | the API key; the same value the API uses |
| `THREATSCOPE_API_URL` | `http://127.0.0.1:8000` | `scheme://host:port` only (no path, no credentials) |
| `THREATSCOPE_TIMEOUT_SECONDS` | `10` | per-request timeout, 0 to 120 |

Inside the backend container the defaults work as they are. No database variables are needed by adapters.

## 4. The API contract the adapters use

`POST /api/v1/events` with header `X-API-Key`; body is the API's `EventIn` (unknown fields are rejected):

| Field | Used by | Notes |
|---|---|---|
| `source`, `event_type`, `occurred_at`, `severity`, `description` | all | required; `occurred_at` is ISO-8601 with a timezone |
| `external_event_id` | all | `file:<hash>`, `domain:<hash>`, `modsec:<hash>` |
| `file_hash` | file | SHA-256; the file event's only indicator |
| `domain` | domain | punycode form; the domain event's only indicator |
| `source_ip` | honeypot | the attacker; the honeypot event's only indicator |
| `metadata` | all | structure, evidence and explanation (limit 64 KB; adapters cap their lists to fit) |

Answers: `201` stored, `409 duplicate_event` (a normal result), `401` wrong key (stop), `422` rejected (counted, run goes on),
`5xx`/timeouts/connection errors (retryable). The ModSecurity adapter stops and retries the failing line next time; the openSquat
adapter stops on connection errors and timeouts but counts a 5xx as failed and goes on; the file analyser counts each one as failed
and goes on with the next file (only a rejected key stops it). Re-running is safe: event ids are stable, so stored events show as duplicates.
The honeypot adapter deliberately sends no `url`, `domain` or `destination_ip`: they would make the honeypot's own address an
indicator shared by every attack.

## 5. Adapter reference (short; the DEVLOG has the full reasoning)

**File analyser** (`file_analyser.py`, `file_formats.py`). Standard library only. SHA-256 (streamed), type from content (PDF,
DOCX, PNG, JPEG, JSON, CSV, TXT/LOG; executables and other zips are identified, not opened), structure metadata, and IPv4s /
domains / URLs found inside (URLs without credentials or query strings; a URL that contains whitespace or control characters is dropped, not trimmed). A damaged
archive part is noted as unreadable, and a file that fails is reported while the rest of the batch goes on. Severity `info`, or `low` when a review marker exists
(PDF JavaScript/OpenAction/Launch/embedded file, DOCX macro/embedded/remote template, data after PNG end, executable header,
extension mismatch). Limits: 10 MB per file, first 1 MB parsed, zip parts capped at 2 MB, lists capped. Found indicators are
evidence in `metadata`, not indicator rows (the API builds indicators only from top-level fields).

**openSquat adapter** (`opensquat_detector.py`, `opensquat_adapter.py`). openSquat's Levenshtein, homograph check and decision
order, returning structured findings. Change that matters: punycode names are decoded before the homograph check (openSquat
would miss every IDN homograph in its own feed). Severity by edit distance, never above `medium`; `metadata.verified=false`.
Keyword, feed and trusted-domain files may be UTF-8, UTF-8 with BOM or UTF-16 with BOM (what PowerShell 5.1 writes). **UTF-16 without a BOM is not supported.**
Modifications are listed in `third_party/NOTICE.md`.

**ModSecurity adapter** (`modsec_parser.py`, `modsec_adapter.py`). One JSON object per line. Category = most severity-weighted
rule hits (`attack_categories` keeps the rest); evaluation rules (949/959/980) are ignored. Never stored: request/response
bodies, cookies and other headers, rule `[data]` payloads. Query values of password/token/key/session-like parameters are
`[redacted]`. `--state` makes reading incremental and rotation-aware; a half-written last line waits for the next run. On a connection
error, timeout or 5xx the run stops and that line is retried next time; a 422 line is skipped.

## 6. Running adapters on host files

The adapters run inside the `backend` container; input files must be visible there.

```powershell
# copy one file in (it is only read)
docker compose cp path\to\samples\invoice.pdf backend:/tmp/invoice.pdf
docker compose exec backend python -m integrations.analyse_file /tmp/invoice.pdf --dry-run     # look first
docker compose exec backend python -m integrations.analyse_file /tmp/invoice.pdf               # then store

# or mount a folder read-only for a one-off run (the API is reached through the compose network)
docker compose run --rm -v "path\to\samples:/samples:ro" -e THREATSCOPE_API_URL=http://backend:8000 backend `
    python -m integrations.modsec_adapter /samples/modsec_audit.log --state /tmp/state.json
```

Real runs add events to the **development database** (unlike the tests), and so does `load-demo.ps1` without `-DryRun`. Use `--dry-run` to preview. A state file kept
inside a throw-away container is lost with it; mount a folder for it if incremental reading must survive.

## 7. A short demo (nothing is stored until the last step)

Demo files live in `backend/demo/` (the only folder the container sees): `brands.txt`, `domains.txt`, `modsec_audit.log`
(five attacks, four from `203.0.113.50`) and `note.txt`. All data is fictional (documentation IP ranges; fictional look-alike names, where `paypa1.com` is a look-alike test name).
The only indicator shared between demo events is the honeypot IP `203.0.113.50`; the look-alike and file events are evidence only.

1. `docker compose run --rm backend python -m integrations.opensquat_adapter --keywords demo/brands.txt --domains demo/domains.txt --dry-run`
   prints the domain events it would send; lines like `paypa1.com` show the detection logic. `rnicrosoft.example` (2 edits from
   "microsoft") is only flagged with `--confidence 2` or higher; the default level 1 finds 3 of the 6 demo domains.
2. `docker compose run --rm backend python -m integrations.modsec_adapter demo/modsec_audit.log --dry-run` shows the honeypot events
   with attack category, severity and the redacted request summary.
3. `docker compose run --rm backend python -m integrations.analyse_file demo/note.txt --dry-run` shows the file event with the
   indicators found inside the note.
4. To store them, run all three with `.\backend\demo\load-demo.ps1` (from the repo root; `-DryRun` previews). If PowerShell says
   "running scripts is disabled", run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first (this window only), or use
   `powershell -ExecutionPolicy Bypass -File .\backend\demo\load-demo.ps1 [-DryRun]`. It adds
   `-e THREATSCOPE_API_URL=http://backend:8000` so the one-off container reaches the API (see section 6). Then open
   `http://127.0.0.1:8000/docs` and call `GET /api/v1/events?source=...` and `GET /api/v1/indicators`: the repeated attacker IP shows a
   rising `sighting_count` and a higher `risk_score` (docs/RISK_SCORING.md).
5. Run step 4 again: everything is "already recorded".

## 8. Verification

This table is the end of Phase 3. Later phases added tests; the current totals (1288 backend) are in the README and the DEVLOG.

| Layer | Tests |
|---|---|
| Phase 2 backend (unchanged in Phase 3) | 685 |
| Shared client and settings | 58 |
| File analyser | 110 |
| openSquat adapter | 101 |
| ModSecurity adapter | 144 |
| Architecture guard + end to end | 49 |
| **Total at the end of Phase 3** | **1147** (928 without PostgreSQL, 219 PostgreSQL-only; no skips) |

The end-to-end suite starts a **real uvicorn server** on the dedicated `threatscope_test` PostgreSQL database and runs the real
command lines of all three adapters over HTTP: scores, indicators and sighting counts, re-runs (no duplicates), wrong key,
unreachable API, dry runs, incremental reading, and a scan of the stored data and the server log for secrets and payloads.
It never touches the development database. Mutation checks (deliberately breaking safety code and watching tests fail) were run
for every adapter; see the DEVLOG.

Commands: `docker compose exec backend pytest -q` (all), `... -m "not postgres"` (quick loop), `... -m postgres`.

## 9. Network monitoring: deferred

Zeek was evaluated (`docs/NETWORK_DECISION.md`). Live capture is impossible here (Docker Desktop cannot see the host network card;
Zeek's Windows support is experimental). The only honest option was Zeek in offline pcap mode with an adapter over its own
`notice.log`, conditional on freeing space on the nearly full disk that holds Docker's data (on the author's machine), pulling the image and supplying a pcap with a real
detection. Those approvals were not given, so the decision is **defer**. The `network` source value, API and scoring already
exist, so adding the adapter later needs no backend change.

## 10. Known limits and hand-off to Phase 4

* File analyser: IPv4 only; PDF streams not decompressed ("no markers" never means "safe"); bare domains only for common TLDs.
* openSquat adapter: first label only for similarity; no DNS/web/certificate checks, so nothing can say a domain is used for abuse;
  generic keywords are noisy.
* ModSecurity adapter: JSON audit format only; no follow mode (run it from a scheduler); category is a heuristic.
* Correlation (Phase 4) can already join on shared indicators the API creates: attacker IP across honeypot and future network
  events, file hash across files, domain across domain findings. Values found *inside* files are in `metadata` for later use.
* Risk scores are experimental and not calibrated (docs/RISK_SCORING.md).
* Deferred Phase 2 review items (Unix timestamps in list filters, body parsed before key check, access logs may show query
  strings) were **not** needed by any adapter and were not changed in Phase 3. Adapters send small POST bodies without query
  strings. Two of the deferred items were fixed later, in Phase 5: the indicator `value` filter is now normalised for types `ip` and
  `domain`, and a request body over 256 KiB gets 413 `payload_too_large`. The cap reads the `Content-Length` header, so a chunked body
  without one is **not** capped; put a reverse proxy in front if the API is ever exposed beyond localhost.
* The look-alike command cannot read UTF-16 files without a BOM; the file analyser drops URLs that contain whitespace or control characters.

## 11. Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| `configuration error: check INGEST_API_KEY` | The key is missing; adapters read `.env` or the environment. `--dry-run` works without it. |
| `the API rejected the API key` | `INGEST_API_KEY` differs from the API's. The run stops at once; nothing was stored. |
| `could not reach the ThreatScope API` | The API is not running or `THREATSCOPE_API_URL` is wrong (from a one-off container use `http://backend:8000`). The failed log line is retried next time. |
| `failed - ... 422 ...` | The API rejected that event; the message names the field. The run continues. |
| `already recorded` | Normal: that event was stored before. |
| Honeypot adapter reads 0 records on a second run | Normal with `--state`: no new complete lines yet. |
| Tests error with "PostgreSQL is mandatory ..." | `docker compose up -d db`, then re-run. |
| `no space left on device`, Docker I/O errors | The disk that holds Docker's data is nearly full. Free space before pulling or building images. |
