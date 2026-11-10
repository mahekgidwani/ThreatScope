# ThreatScope Phase 5 Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the confirmed defects and demo-readiness gaps found by the Phase 5 whole-project review, without adding features or dependencies.

**Architecture:** Small, test-first fixes in the existing layers (dashboard, backend API/services, adapters, docs). Every fix has one failing test first. No refactors, no new dependencies, no schema changes.

**Tech Stack:** Python 3.12 (backend container) / 3.13 (host), FastAPI, SQLAlchemy 2, PostgreSQL 16, Streamlit 1.43 (AppTest), pytest, httpx MockTransport.

**Spec:** The Phase 5 review report (this session, 2026-11-10). Finding IDs below (DASH-01, INT-01, ...) match that report. The "Findings in scope" table is the working spec.

## Global Constraints

- Work on a new branch `phase5/review-fixes` created from `phase4/dashboard`. Never merge, rebase, reset, stash or force anything. Do not touch `main` or `phase3/integrations`.
- Never read, print or copy `.env`. Never run `docker compose down -v`, never delete volumes, databases or demo events.
- Ask the user before any Docker image pull or build (C: drive is nearly full). Use `docker compose run --rm backend ...` with images that already exist. If an image is missing, stop and ask.
- Never run `backend/demo/load-demo.ps1` against the dev database without asking the user first. Verify demo files with `--dry-run` and unit tests only.
- Published ports stay `127.0.0.1` only.
- No new dependencies in any requirements file.
- Test commands: dashboard `cd dashboard; python -m pytest -q` (host). Backend `docker compose run --rm backend pytest -q <path>` (SQLite + real PostgreSQL; `-m "not postgres"` for a quick loop). PostgreSQL tests are mandatory and must never be skipped.
- Reported baselines are unverified. Task 0 records the real numbers.
- Commit after each task. Messages end with: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`
- Lean rule: smallest change that fully fixes the finding. A known limit gets a `shortcut: <limit>, <when to upgrade>` comment.

## Review Focus

Input classes the findings imply but no existing test covers (each is pinned in the named task):

1. Events dated 1900, 1970 or year 9999 on every dashboard page, not just Overview (Task 2).
2. A 503 in the middle of a stateful ModSecurity run, then a rerun that must resume at the failed line (Task 6).
3. Mixed-case and non-ASCII domain / IPv6 text in the indicator `value` filter (Task 9).
4. Control characters (NUL, ESC) inside URLs found in files and PDFs (Task 7).
5. A minute or 5-minute boundary falling between two Streamlit reruns (Task 1).

## Findings in scope

| Tier | IDs | Task |
|---|---|---|
| 1 Must | DASH-01, DASH-02, INT-01, DEMO-01, DASH-03 | 1, 2, 6, 8, 3 |
| 2 Should | BACK-03, BACK-05, BACK-02, LOG-01, BACK-01, INT-02, INT-03, INT-04, TEST-01, TEST-02, TEST-03, TEST-06, TEST-07, DASH-04, DASH-06, DASH-07, docs DOC-01..DOC-10, LIC-01, LOG-02, DEP-01 (docs only), BACK-06 (comment only) | 0, 4, 5, 7, 9–14 |
| Deferred (not in this plan) | BACK-04 TrustedHost, BACK-07..13, BACK-10 URL canonicalisation, DASH-05, DASH-08..11, INT-05..13, DEP-02..05, TEST-04, 05, 08..13 | ask user after Task 15 |

Two findings were downgraded after analysis. DEP-01: `dashboard/app.py:12` calls `st.logo("assets/logo.svg")`, a cwd-relative path, so running from the repo root crashes before any page renders. The fix is the documented command only. BACK-06: fix the misleading comment in `config.py`, not the required fields.

## Skill map (applies to every task)

Always: `superpowers:test-driven-development` (red, green, commit), `superpowers:verification-before-completion` (run the command, read the output, before any "done"), `ponytail:ponytail` (smallest diff), `superpowers:systematic-debugging` when a test fails for an unexpected reason.
Per-task skills are listed in each task. Skills considered and not used: impeccable (no visual redesign), claude-api, loop/schedule, database-migrations (no schema change), deep-research, all language-specific skills for other stacks.

---

## Task 0: Branch, baseline and test isolation (TEST-07)

**Skills:** `superpowers:using-git-worktrees` (decision: work in place, one branch is enough), `ecc:docker-patterns` (compose run semantics), `ecc:python-testing`, `superpowers:verification-before-completion`.

**Files:**
- Modify: `dashboard/tests/conftest.py` (add autouse fixture)
- Test: `dashboard/tests/test_config.py`
- Plan file `docs/superpowers/plans/2026-11-10-threatscope-phase5-review-fixes.md` already exists (untracked).

**Interfaces:**
- Produces: autouse fixture `no_real_api_key(monkeypatch)` in `dashboard/tests/conftest.py`. Later dashboard tests rely on the suite not reading a real key.

- [ ] **Step 1: Create the branch.** `git switch -c phase5/review-fixes` from `phase4/dashboard` (the working tree has only this untracked plan). Expected: `git branch --show-current` prints `phase5/review-fixes`.
- [ ] **Step 2: Docker preflight (user action).** Ask the user to start Docker Desktop. Then `docker images` (no pull). Expected: the backend image and `postgres:16` are listed. If either is missing, stop and ask.
- [ ] **Step 3: Record the baseline.** Run `cd dashboard; python -m pytest -q` and `docker compose run --rm backend pytest -q`. Write the exact pass/fail counts into the Task 15 notes. Any pre-existing failure is reported to the user before continuing.
- [ ] **Step 4: Write the failing test** `dashboard/tests/test_config.py::test_suite_never_sees_a_real_api_key`: `load_settings().ingest_api_key` is `None` or empty inside the suite. Run it. Expected: FAIL when a real `INGEST_API_KEY` reaches the process; if it passes locally, note that and keep the fixture anyway.
- [ ] **Step 5: Implement** the autouse fixture in `dashboard/tests/conftest.py`: `monkeypatch.setenv("INGEST_API_KEY", "")`. (`test_incidents_page` sets its own key in a later fixture, which overrides this.)
- [ ] **Step 6: Run** the dashboard suite. Expected: baseline count, all pass.
- [ ] **Step 7: Commit** `git add docs/superpowers/plans dashboard/tests/conftest.py dashboard/tests/test_config.py` with `test: isolate dashboard tests from the real API key; add Phase 5 fix plan`.

---

## Task 1: Relative time presets break Events paging and CSV (DASH-01)

**Skills:** `superpowers:systematic-debugging` (root cause is an unstable `datetime.now()` inside a compared signature), `ecc:click-path-audit` (trace click, rerun, session_state sequences), `ecc:python-testing`, `ecc:python-patterns`.

**Files:**
- Modify: `dashboard/ts_dashboard/events.py:77-84` (`time_range`)
- Test: `dashboard/tests/test_events.py`, `dashboard/tests/ui/test_events_page.py`, `dashboard/tests/ui/test_reports_page.py`

**Interfaces:**
- Consumes: `time_range(preset: str, now: datetime, start_date=None, end_date=None) -> tuple[datetime | None, datetime | None]`, called from `views/events.py:65` and `views/reports.py:40`.
- Produces: same signature. For presets in `RANGE_PRESETS` the returned `start` is `now - span` rounded **down** to a multiple of the new constant `RANGE_BUCKET = timedelta(minutes=5)`. Custom ranges and "All time" are unchanged. Rounding down only widens the window by under 5 minutes.

- [ ] **Step 1: Failing unit tests** in `test_events.py`:
  - `test_relative_start_is_stable_within_a_bucket`: `time_range("Last 24 hours", t, ...)` and the same call with `t + timedelta(seconds=137)` return equal `start` (choose `t` at 12:00:30 UTC so both fall in one bucket). Use the real preset names from `RANGE_PRESETS`.
  - `test_relative_start_never_narrows_the_window`: `start <= now - span` and `now - span - start < RANGE_BUCKET`.
  - `test_relative_start_has_no_microseconds`.
- [ ] **Step 2: Failing UI test** `test_next_page_survives_a_rerun_with_a_relative_range` in `ui/test_events_page.py`: backend with at least 3 pages of events; patch `views.events.datetime` with a stub whose `now(tz)` returns a base time plus 1 second per call (stays inside one bucket, reproduces the drift); select "Last 24 hours", click Next, assert page 2 is shown after the rerun and `ev_page == 1`.
- [ ] **Step 3: Failing UI test** `test_csv_download_stays_available_after_prepare` in `ui/test_reports_page.py`, same stubbed clock and a relative range: click "Prepare events CSV", rerun, assert "filters changed" is absent and "Download events CSV" is present.
- [ ] **Step 4: Run** the three tests. Expected: FAIL (page resets to 1; "filters changed" shown).
- [ ] **Step 5: Implement** the rounding in `time_range` plus `RANGE_BUCKET`, with a `shortcut:` comment (a click that straddles a 5-minute boundary still resets once).
- [ ] **Step 6: Run** `cd dashboard; python -m pytest -q`. Expected: all pass.
- [ ] **Step 7: Commit** `fix(dashboard): stable relative time ranges so paging and CSV survive reruns`.

---

## Task 2: One out-of-range timestamp crashes Overview (DASH-02)

**Skills:** `superpowers:systematic-debugging`, `ecc:error-handling`, `ecc:python-patterns`, `ecc:python-testing`.

**Files:**
- Modify: `dashboard/ts_dashboard/overview.py` (`_floor`, `build_trend`, `Trend`), `dashboard/views/overview.py` (one note line)
- Test: `dashboard/tests/test_overview.py`, `dashboard/tests/test_components.py`, `dashboard/tests/ui/test_app.py`, plus the Events, Correlation and Indicators page tests

**Interfaces:**
- Produces: `_floor(moment: datetime, step: timedelta) -> datetime` implemented as `epoch + (moment - epoch) // step * step` (no `fromtimestamp`). `Trend` gains `outside_range: int = 0` (default keeps existing callers valid). New constant `TREND_WINDOW = TREND_STEPS[-1] * (MAX_TREND_BUCKETS - 1)`. `build_trend` ignores events older than `now - TREND_WINDOW` or newer than `now + TREND_STEPS[0]`, counts them in `outside_range`, and returns `None` if nothing is left.

- [ ] **Step 1: Failing tests** in `test_overview.py`: `test_build_trend_survives_year_1900_1970_and_9999` (events at `now` plus one outlier each; no exception; `trend.outside_range == 1`; bucket count `<= MAX_TREND_BUCKETS`); `test_build_trend_all_events_outside_window_returns_none`; `test_floor_matches_old_behaviour_for_normal_dates` (equals the previous result for a 2026 date and each step).
- [ ] **Step 2: Failing page tests** (Review Focus 1): Overview in `ui/test_app.py` with a year-9999 and a 1900 event renders with no exception and shows the "outside the chart range" note. Add assertions that `fmt_time` renders year 1 and 9999 without raising (`test_components.py`), and that the Events, Correlation and Indicators pages each render one far-dated event without exception.
- [ ] **Step 3: Run.** Expected: FAIL with `OSError` on this Windows host.
- [ ] **Step 4: Implement** the changes above and the one-line note in `views/overview.py`, shown only when `trend.outside_range`.
- [ ] **Step 5: Run** `cd dashboard; python -m pytest -q`. Expected: all pass.
- [ ] **Step 6: Commit** `fix(dashboard): ignore out-of-range event times in the trend instead of crashing`.

---

## Task 3: Credentials in URLs shown and exported (DASH-03)

**Skills:** `ecc:security-review`, `ecc:python-patterns`, `ecc:python-testing`.

**Files:**
- Modify: `dashboard/ts_dashboard/components.py` (`primary_indicator`, `events_table`, `event_detail`, `indicators_table`, `indicators_full_table`, `incident_detail`), `dashboard/ts_dashboard/reports.py` (`_event_rows`, the recurring-indicators table)
- Test: `dashboard/tests/test_components.py`, `dashboard/tests/test_reports.py`

**Interfaces:**
- Consumes: `redact(value: Any, _depth: int = 0) -> Any` from `ts_dashboard/redact.py` (already masks `scheme://user:pass@`).
- Produces: every URL, description and indicator value that is displayed or written to Markdown passes through `redact` before `html.escape` / `_cell`. Add one helper `_shown(text: str) -> str` in `components.py` only if the same two-call pattern repeats more than three times.

- [ ] **Step 1: Failing tests:** `test_credentials_in_urls_are_hidden_everywhere`, parametrised over `events_table`, `event_detail`, `indicators_table`, `indicators_full_table`, `incident_detail` and the report / incident Markdown builders. Event URL `http://admin:hunter2@evil.test/x`, a URL indicator with the same value, and a description containing the same URL. Assert `hunter2` and `admin:` are absent and `[redacted]` is present.
- [ ] **Step 2: Run.** Expected: FAIL (secret appears).
- [ ] **Step 3: Implement** the `redact` calls at the display boundary. Update the "secrets hidden" wording only if it becomes inaccurate.
- [ ] **Step 4: Run** the dashboard suite. Expected: all pass; existing escaping tests unchanged.
- [ ] **Step 5: Commit** `fix(dashboard): hide URL credentials in tables, details and Markdown reports`.

---

## Task 4: Small dashboard correctness (DASH-04, DASH-06, DASH-07)

**Skills:** `ecc:click-path-audit` (form state after submit), `ecc:python-testing`, `ponytail:ponytail`.

**Files:**
- Modify: `dashboard/views/incidents.py:141-157` (`_create_panel`), `dashboard/views/overview.py:27`, `dashboard/views/reports.py:116,146`, `dashboard/ts_dashboard/reports.py` (high-risk subtitle in the Markdown)
- Test: `dashboard/tests/ui/test_incidents_page.py`, `ui/test_app.py`, `ui/test_reports_page.py`, `test_reports.py`

**Interfaces:**
- Produces: create-form widget keys include `st.session_state["ic_form_n"]` (already bumped by `_done`). The percent formatter returns `"<1%"` when `0 < part/whole < 0.005`.

- [ ] **Step 1: Failing tests:** `test_create_form_is_cleared_after_a_successful_create` (after creating, title and notes inputs are empty and the selected event ids are cleared; pressing Create again without new input does not create a second incident); `test_kpi_is_named_high_severity` (label "High severity events"); `test_small_share_shows_less_than_one_percent`; `test_high_risk_report_says_newest_200_per_severity_when_sampled`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the key change, the rename and the formatter. Update any existing test that asserts the old label.
- [ ] **Step 4: Run** the dashboard suite. Expected: all pass.
- [ ] **Step 5: Commit** `fix(dashboard): clear incident form after create; clearer KPI labels and sampling note`.

---

## Task 5: Compose port test and Status page test (TEST-01, TEST-02)

**Skills:** `ecc:docker-patterns`, `ecc:python-testing`, `ecc:security-review`.

**Files:**
- Modify: `dashboard/tests/test_architecture.py`
- Create: `dashboard/tests/ui/test_status_page.py`

**Interfaces:**
- Produces: `published_ports(compose_text: str) -> list[str]` (test helper, text-based, no PyYAML): returns every list entry under any `ports:` key, comments ignored. It lives in the dashboard architecture test because dashboard tests run on the host where `docker-compose.yml` is readable (the backend container mounts only `./backend`).

- [ ] **Step 1: Tests:** `test_every_published_port_is_loopback_only` (real `docker-compose.yml`: all entries start with `127.0.0.1:`); `test_the_port_check_catches_a_public_binding` (feeds `ports:\n  - "5432:5432"` to `published_ports` and asserts the loopback check would fail); `test_status_page_renders_ready_and_database_down_and_api_down` (AppTest with `TS_PAGE=status`; cases: healthy, a 503 body with database down, a connection error; no exception; each shows its message).
- [ ] **Step 2: Run.** Expected: the helper tests and the status test FAIL until they exist; the real-compose test passes immediately (it is a guard, not a fix; say so in the commit).
- [ ] **Step 3: Implement** the helper and the AppTest file following `ui/test_events_page.py` (`HARNESS`, `FakeBackend`). Read `fake_backend.py` first for the health response shape.
- [ ] **Step 4: Run** the dashboard suite. Expected: all pass.
- [ ] **Step 5: Commit** `test: guard compose ports and cover the Status page`.

---

> Tasks 6 to 13 and 15 run backend tests in Docker. Confirm Docker is running (Task 0, step 2).

## Task 6: ModSecurity adapter loses events on 5xx (INT-01)

**Skills:** `superpowers:systematic-debugging`, `ecc:error-handling`, `ecc:python-testing`, and the `ecc:silent-failure-hunter` agent for review.

**Files:**
- Modify: `backend/integrations/modsec_adapter.py:22-24,161-178` and its module docstring (line 14), `docs/INTEGRATIONS.md` (the sentence near line 65)
- Test: `backend/tests/integrations/test_modsec_adapter.py`

**Interfaces:**
- Consumes: `IntegrationError.retryable: bool` (class attribute; `ApiConnectionError`, `ApiTimeoutError`, `ApiServerError` are True), `fake_client(handler)` and `error_reply(status, code)` from `tests/integrations/fakes.py`.
- Produces: in `_run`, after the `ApiAuthError` branch, a single `except IntegrationError as exc:` that, when `exc.retryable`, prints `"{exc}. Stopping."`, counts a failure, sets `aborted = True` and `break`s **before** `offset = end`. Non-retryable errors (422) keep today's behaviour: counted failed, line skipped. Remove imports that become unused.

- [ ] **Step 1: Failing tests:** `test_503_stops_the_run_and_keeps_the_failed_line_for_next_time` (log with 3 valid lines, `--state`; handler returns 201 for line 1 and 503 for line 2; assert exit code 1, the saved offset equals the end of line 1 only, line 3 was never sent); `test_rerun_after_outage_resumes_at_the_failed_line` (same state file, handler now 201; lines 2 and 3 stored, line 1 not resent); `test_422_is_counted_failed_and_skipped` (pins the unchanged behaviour: offset advances past the rejected line).
- [ ] **Step 2: Run** `docker compose run --rm backend pytest -q tests/integrations/test_modsec_adapter.py`. Expected: the first two FAIL.
- [ ] **Step 3: Implement** the branch change; fix the docstring and the INTEGRATIONS sentence so they say connection errors, timeouts and 5xx stop the run.
- [ ] **Step 4: Run** `docker compose run --rm backend pytest -q tests/integrations`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(modsec): stop and retry on retryable API errors instead of skipping the line`.

---

## Task 7: File analyser and look-alike CLI hardening (INT-02, INT-03, INT-04)

**Skills:** `ecc:security-review`, `ecc:error-handling`, `ecc:regex-vs-llm-structured-text` (regex vs explicit checks for URL text), `ecc:python-testing`.

**Files:**
- Modify: `backend/integrations/file_analyser.py:109-124` (`_clean_url`), `backend/integrations/analyse_file.py:45-69` (`_run`), `backend/integrations/file_formats.py:~163` (`_read_part` exception tuple), `backend/integrations/opensquat_adapter.py:52-62` (`iter_lines`)
- Test: `tests/integrations/test_file_analyser_core.py`, `test_file_cli.py`, `test_file_formats.py`, `test_opensquat_cli.py`

**Interfaces:**
- Produces: `_clean_url` returns `None` when any character has `ord(c) < 0x21 or ord(c) == 0x7F`. `_read_part` also catches `lzma.LZMAError`. `analyse_file._run` has a final `except Exception as exc:  # noqa: BLE001` per path that prints `"{label}: analysis failed - {type(exc).__name__}"`, counts a failure and continues. `iter_lines(path)` opens with `encoding="utf-16"` when the first two bytes are `b"\xff\xfe"` or `b"\xfe\xff"`, otherwise `encoding="utf-8-sig"`.

- [ ] **Step 1: Failing tests (INT-02):** `test_urls_with_control_characters_are_dropped` (text with `http://x.com/a\x00b` and `http://x.com/a\x1bb`: neither appears in `indicators["urls"]`; a PDF `/URI (http://x.com/\x00)` likewise; the resulting event passes `EventIn` validation).
- [ ] **Step 2: Failing tests (INT-03):** `test_corrupt_lzma_member_is_a_clean_error` (build a docx-like zip with `ZIP_LZMA`, corrupt the payload; `analyse_file` raises nothing except `FileAnalysisError`); `test_one_bad_file_does_not_stop_the_batch` (monkeypatch `analyse_file` to raise `lzma.LZMAError` for the first path; the second path is still stored; exit code 1).
- [ ] **Step 3: Failing tests (INT-04):** `test_domain_list_encodings_all_work` (the same three domains written as UTF-8, UTF-8 with BOM and UTF-16 with BOM give identical "checked N" results and the first domain is not dropped).
- [ ] **Step 4: Run.** Expected: all new tests FAIL.
- [ ] **Step 5: Implement** the four changes above.
- [ ] **Step 6: Run** `docker compose run --rm backend pytest -q tests/integrations`. Expected: all pass.
- [ ] **Step 7: Commit** `fix(integrations): drop control-character URLs, survive corrupt archives, accept BOM/UTF-16 lists`.

---

## Task 8: Demo data and loader (DEMO-01)

**Skills:** `ecc:docs-governance`, `ecc:python-testing`, `ecc:search-first` (reuse the sample builders in `tests/integrations/samples.py` and `modsec_samples.py`), `ponytail:ponytail`.

**Files:**
- Create: `backend/demo/domains.txt`, `backend/demo/modsec_audit.log`, `backend/demo/note.txt` (harmless text with URLs and the same attacker IP), `backend/demo/load-demo.ps1`, `backend/tests/integrations/test_demo_files.py`
- Modify: `README.md` "Try it" (point to the loader), `docs/INTEGRATIONS.md` §7 (replace the `/tmp/...` paths)

**Interfaces:**
- Produces: demo files under `backend/demo/` (the only folder bind-mounted into the container). `load-demo.ps1` is run from the repo root and calls the three adapters with `docker compose run --rm backend python -m integrations.<adapter> demo/<file>`. Exact adapter arguments come from `docs/INTEGRATIONS.md` §7 and each adapter's `_parser()`.
- The demo set must produce at least 3 events and at least one IP or domain shared by 2 or more events, so Correlation and the repeat bonus are visible.

- [ ] **Step 1: Failing test** `test_demo_files_build_valid_events_with_a_shared_indicator`: run each demo file through its adapter's pure builders (`modsec_parser.build_event` per log line; `opensquat_detector.find_squatting` + `build_event`; `file_analyser.analyse_file` + `build_event`), validate every event with `EventIn`, assert `>= 3` events and that `extract_indicators` over all events yields one indicator value appearing in at least two events.
- [ ] **Step 2: Run.** Expected: FAIL (files missing).
- [ ] **Step 3: Create** the demo files from the existing sample builders (fictional IPs in 203.0.113.0/24, `.example` or look-alike domains as the sample tests use, no real malware).
- [ ] **Step 4: Create** `load-demo.ps1` (three adapter calls, prints counts, refuses to run if `docker compose ps` shows the backend not running).
- [ ] **Step 5: Verify without writing data:** run each adapter with `--dry-run` through `docker compose run --rm backend ...` and confirm events print. Do **not** run the loader against the dev database; ask the user whether to run it.
- [ ] **Step 6: Run** `docker compose run --rm backend pytest -q tests/integrations/test_demo_files.py`. Expected: PASS.
- [ ] **Step 7: Commit** `feat(demo): add demo data and a loader so a fresh clone has events to show`.

---

## Task 9: Indicator `value` filter normalisation (BACK-03)

**Skills:** `ecc:fastapi-patterns`, `ecc:api-design`, `ecc:postgres-patterns`, `ecc:python-testing`.

**Files:**
- Modify: `backend/app/services/indicator_service.py:10-26` (`list_indicators`)
- Test: `backend/tests/api/test_read_api.py`

**Interfaces:**
- Consumes: `canonical_ip(value: str) -> str`, `normalise_domain(value: str) -> str` (`app.schemas.event`, both raise `ValueError`), `InvalidFilterError(message)` (`app.errors`). Mirror the pattern in `event_service.py:144-153`.
- Produces: when `type` is `ip` or `domain` and `value` is given, the value is normalised before comparison; invalid text raises `InvalidFilterError("value is not a valid <type>")` (HTTP 422). Other types and `type=None` stay exact-match. The dashboard Indicators search needs no change.

- [ ] **Step 1: Failing tests** (Review Focus 3; they run on SQLite and PostgreSQL via the existing fixtures): ingest events with domain `Example.COM`, IP `2001:0DB8::1` and a Unicode domain (`bücher.de`). `GET /indicators?type=domain&value=Example.COM` returns total 1; `type=ip&value=2001:0DB8::1` returns total 1; `type=domain&value=B%C3%BCcher.DE` returns total 1; `type=ip&value=not-an-ip` returns 422 with the standard envelope and does not echo the input; `type=url&value=<exact url>` is unchanged.
- [ ] **Step 2: Run** `docker compose run --rm backend pytest -q tests/api/test_read_api.py`. Expected: FAIL (empty pages).
- [ ] **Step 3: Implement** the normalisation in `list_indicators`; update the docstring ("exact match after normalisation for ip and domain").
- [ ] **Step 4: Run** `docker compose run --rm backend pytest -q tests/api tests/db`. Expected: all pass on both backends.
- [ ] **Step 5: Commit** `fix(api): normalise ip/domain values in the indicator filter like the events filters`.

---

## Task 10: URL host IPs with scope ids (BACK-05)

**Skills:** `ecc:python-patterns`, `ecc:security-review`, `ecc:python-testing`.

**Files:**
- Modify: `backend/app/services/indicator_extractor.py:11-18` (`_host_indicator`)
- Test: `backend/tests/unit/test_indicator_extractor.py`

**Interfaces:**
- Consumes: `canonical_ip` (import from `app.schemas.event`, next to the existing `normalise_domain` import).
- Produces: `_host_indicator` tries `canonical_ip(host)` instead of `ipaddress.ip_address`. A scope-id host falls through to the domain attempt, which rejects it, so only the URL indicator remains.

- [ ] **Step 1: Failing tests:** `test_url_host_with_scope_id_creates_no_ip_indicator` (`http://[fe80::1%25eth0]/x` yields the url indicator and no `ip` indicator containing `%`); `test_url_host_ipv6_is_canonical` (`http://[2001:DB8::1]/` yields `ip` `2001:db8::1`).
- [ ] **Step 2: Run** `docker compose run --rm backend pytest -q tests/unit/test_indicator_extractor.py`. Expected: the first FAILS.
- [ ] **Step 3: Implement** the swap; drop the `ipaddress` import if unused.
- [ ] **Step 4: Run** `docker compose run --rm backend pytest -q tests/unit tests/db`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(indicators): never store an IPv6 scope id from a URL host as an ip indicator`.

---

## Task 11: Incident id range (BACK-02)

**Skills:** `ecc:postgres-patterns`, `ecc:fastapi-patterns`, the `ecc:database-reviewer` agent, `ecc:python-testing`.

**Files:**
- Modify: `backend/app/api/incidents.py:38,50`
- Test: `backend/tests/api/test_incidents_api.py`

**Interfaces:**
- Produces: `incident_id: int = Path(ge=1, le=2_147_483_647)` on `get_one_incident` and `patch_incident` (`from fastapi import Path`). Out-of-range ids return the existing 422 `validation_error` envelope.

- [ ] **Step 1: Failing tests:** `test_incident_id_beyond_int4_is_rejected_not_a_500` for `GET /api/v1/incidents/2147483648` and for `PATCH` with a valid key; id `0` and negative ids also give 422; id `2147483647` that does not exist gives 404.
- [ ] **Step 2: Run.** Expected: on PostgreSQL the first FAILS with 500. This also confirms or refutes the review's unverified claim; record which.
- [ ] **Step 3: Implement** the `Path` bounds.
- [ ] **Step 4: Run** `docker compose run --rm backend pytest -q tests/api`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(api): reject incident ids outside the int4 range with 422`.

---

## Task 12: Request hardening (LOG-01, BACK-01)

**Skills:** `ecc:security-review`, `ecc:fastapi-patterns`, `ecc:api-design`, `ecc:python-testing`, and the `ecc:fastapi-reviewer` agent.

**Files:**
- Modify: `backend/app/main.py:38-49` (access log and a size-limit middleware), `backend/app/schemas/event.py` (`domain`, `source_ip`, `destination_ip`), `backend/app/schemas/incident.py` (`title`, `summary`)
- Test: `backend/tests/api/test_startup.py`, `backend/tests/api/test_events_api.py`, `backend/tests/api/test_incidents_api.py`

**Interfaces:**
- Consumes: `error_response(...)` from `app.errors` for the 413 body (same envelope as other errors).
- Produces: the access log line uses `%r` for the path (`"%s %r %s %.1fms"`). Module constant `MAX_REQUEST_BYTES = 256 * 1024` and an HTTP middleware that returns 413 when `Content-Length` exceeds it, with a `shortcut:` comment (chunked bodies without Content-Length are not capped; put a reverse proxy in front if the API is ever exposed). `Field(max_length=...)` on the fields above, reusing the constants the validators already use for title (200) and summary (5000); `domain` 512 and IP fields 64 (longer inputs are rejected anyway).

- [ ] **Step 1: Failing tests:** `test_access_log_does_not_contain_raw_newlines_from_the_path` (`GET /x%0Aforged` with `caplog`: no record message contains a raw newline); `test_oversized_body_is_413_with_the_error_envelope` (`Content-Length` above the cap, no key, `POST /api/v1/events`); `test_overlong_domain_ip_title_summary_are_422` (each field one character over its limit).
- [ ] **Step 2: Run.** Expected: all FAIL.
- [ ] **Step 3: Implement** the log format, the middleware and the `max_length`s.
- [ ] **Step 4: Run** `docker compose run --rm backend pytest -q`. Expected: the whole backend suite passes (SQLite + PostgreSQL).
- [ ] **Step 5: Commit** `fix(api): escape the access-log path, cap request size and field lengths`.

---

## Task 13: Error-leak coverage on read and incident routes; safer live probes (TEST-03, TEST-06)

**Skills:** `ecc:python-testing`, `ecc:security-review`, `ecc:ai-regression-testing` (sandbox-style tests that need no live DB), the `ecc:silent-failure-hunter` agent.

**Files:**
- Modify: `backend/tests/api/test_events_api.py` or `test_health.py` (reuse the dead-engine helper in `test_health.py`), `dashboard/tests/live/test_live_api.py`

**Interfaces:**
- Consumes: the dead-engine technique already used in `test_health.py`.
- Produces: a parametrised test over `GET /api/v1/events`, `/events/{uuid}`, `/indicators`, `/incidents`, `/incidents/1` that points the app at the dead engine and asserts 503, the standard error envelope, and that the body contains neither the DB host, the driver name nor any `psycopg` text.

- [ ] **Step 1: Write** `test_database_down_is_a_clean_503_on_every_read_route`. Run it. Expected: PASS if the handlers are sound (a coverage gap, not a known bug). If it FAILS, stop: that is a new confirmed defect; report it before fixing.
- [ ] **Step 2: Change** the live probes in `test_live_api.py::test_reads_are_open_and_writes_need_the_key` to send an invalid body (`{}`) with no key to `POST /incidents` and `PATCH /incidents/1`, so a fail-open auth would give 422 and never create or close a real incident. Keep the expected 401. Remove the hard-coded demo event UUID from those probes.
- [ ] **Step 3: Run** `docker compose run --rm backend pytest -q tests/api`. Expected: pass. The live test runs only in Task 15, with the user's approval.
- [ ] **Step 4: Commit** `test: cover DB-down responses on all read routes; make live auth probes fail safe`.

---

## Task 14: Documentation and viva readiness (DOC-01..DOC-10, LIC-01, LOG-02, DEP-01, BACK-06)

**Skills:** `ecc:docs-governance`, `ecc:living-docs-governance`, `ecc:update-docs`, `ecc:architecture-decision-records` (record the deferred-items decision). Plain, short sentences; do not invent features.

**Files:**
- Modify: `README.md`, `PRODUCT.md`, `docs/DEVLOG.md`, `docs/DASHBOARD.md`, `docs/RISK_SCORING.md`, `docs/INTEGRATIONS.md`, `docs/superpowers/specs/2026-11-07-threatscope-phase2-backend-design.md`, `third_party/NOTICE.md`, `.env.example`, `backend/app/config.py` (comment only, near line 45)

**Interfaces:** none (documentation only).

- [ ] **Step 1: README.** Add: Python 3.11+ (3.12 recommended) and a venv recipe for the dashboard (`python -m venv .venv; .\.venv\Scripts\Activate.ps1`); a one-diagram architecture block (adapters to API to PostgreSQL, dashboard reads via the API); the dashboard section moved above Tests, with the launch command `streamlit run app.py --server.address 127.0.0.1` run from `dashboard/`; "the key is picked up from `.env`; set `INGEST_API_KEY=` empty to force read-only"; a "Known limitations" block linking `docs/DASHBOARD.md` and `docs/INTEGRATIONS.md` (correlation sees the newest 1,000 events, unauthenticated reads, no cap on chunked request bodies, the uvicorn access log prints query strings); soften "replaced with *** in logs" to match `logging_config.py` (root logger only, exact strings); list `dashboard/`, `DASHBOARD.md`, `PRODUCT.md`, `DESIGN.md` in Project layout; replace the machine-specific `C:` / `F:\` wording with generic text; point "Try it" at `backend/demo/load-demo.ps1`.
- [ ] **Step 2: PRODUCT.md** constraint 2: the dashboard reads `INGEST_API_KEY` for incident writes. **DASHBOARD.md:** tests need `pip install -r requirements-dev.txt`. **`.env.example`:** add a commented `# DATABASE_URL=`. **`config.py`:** fix the comment so it says the POSTGRES_* values are still required.
- [ ] **Step 3: DEVLOG** gets a Phase 4 section (link DASHBOARD.md, the incident API extension, test totals filled in during Task 15) and a Phase 5 section (what the review found, what was fixed, what was deferred and why). **RISK_SCORING / INTEGRATIONS / NOTICE / `risk_scoring.py` docstring:** past tense for Phase 4 ("kept these weights; incidents roll up the maximum"). **Phase 2 spec line 116:** add a "superseded: the repeat bonus is exact" note. **INTEGRATIONS §2.1:** reword to "only the shared validators and logging setup are imported from `app`".
- [ ] **Step 4: NOTICE.md:** add rows for Streamlit (Apache-2.0), Plotly (MIT), httpx (BSD-3-Clause) and the OWASP Core Rule Set (Apache-2.0, conventions only), plus a sentence that GPL-3.0 applies project-wide because of the adapted openSquat code. Reference repositories: README says three, `PHASE1_AUDIT.md` lists four. **Ask the user** which are the three and for upstream URLs not already in the repo; do not guess URLs.
- [ ] **Step 5: Verify** every changed command and number against the code: run each read-only documented command (`docker compose config`, `streamlit run --help`) and re-check each quoted constant with grep. Test counts stay as placeholders until Task 15.
- [ ] **Step 6: Commit** `docs: fix README prerequisites and accuracy, add Phase 4/5 devlog, notices and limitations`.

---

## Task 15: Full verification, independent review, hand-off

**Skills:** `superpowers:verification-before-completion`, `superpowers:requesting-code-review`, `ecc:python-review`, `ecc:fastapi-review`, `ecc:code-review` (local mode on the branch diff), `ecc:security-review`, `ecc:ai-regression-testing` (the reviewer must be a fresh agent, not the author), `ecc:conventional-commit-review`, `ecc:git-workflow`, `superpowers:finishing-a-development-branch`.

- [ ] **Step 1: Full runs, fresh.** `docker compose run --rm backend pytest -q` (expect all pass, zero skips, PostgreSQL tests included); `cd dashboard; python -m pytest -q`; the dashboard container run if the Phase 4 setup supports it (`docs/DASHBOARD.md`). Record exact counts.
- [ ] **Step 2: Live suite (ask the user first).** With the stack up: `cd dashboard; python -m pytest -m live -q`. It reads the dev database and sends only invalid-body 401 probes. Expect 10 passed.
- [ ] **Step 3: Fill the real test counts** into README and DEVLOG; commit `docs: record verified test totals`.
- [ ] **Step 4: Independent review.** Dispatch fresh read-only agents (`ecc:python-reviewer`, `ecc:fastapi-reviewer`, `ecc:security-reviewer`) on `git diff phase4/dashboard...phase5/review-fixes`, each told: review only, no edits. Fix anything Critical or High they confirm, with a test, as a new commit.
- [ ] **Step 5: Re-check the review.** For each Tier 1 and Tier 2 finding, state fixed (commit hash and test name), not fixed, or changed. Run `git status` (clean) and confirm no `.env`, demo data or volume was touched.
- [ ] **Step 6: Hand-off.** Report results, the deferred list, and the options from `superpowers:finishing-a-development-branch`. Do not merge without the user's decision.

---

## Self-review

1. **Spec coverage:** every Tier 1 and Tier 2 ID in the table maps to a task; deferred IDs are listed. BACK-06 and DEP-01 are docs-only on purpose (reasons given).
2. **Step scan:** each code step names file, function and signature; each test step names the test and its assertions. No "TBD".
3. **Type consistency:** `time_range` signature unchanged; `Trend.outside_range` has a default; `canonical_ip` and `normalise_domain` names match `app.schemas.event`; `IntegrationError.retryable` matches `client.py`.
4. **Review Focus:** all five items have a named test in Tasks 1, 2, 6, 7, 9.
5. **Proportion:** 16 tasks for about 25 findings; bodies are signatures and assertions, not implementations.
6. **Open risks:** Tasks 6 to 13 and 15 need Docker Desktop running; if images are missing the plan stops and asks. Task 1's UI test stubs `views.events.datetime`; if AppTest cannot patch it, patch `ts_dashboard.events.RANGE_BUCKET` to a very large value instead and note the change.
