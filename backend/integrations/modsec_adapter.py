"""Command line: read a ModSecurity JSON audit log and send honeypot events to ThreatScope.

    python -m integrations.modsec_adapter LOGFILE [--state FILE] [--max-events N] [--dry-run]

LOGFILE is the ModSecurity audit log written with `SecAuditLogFormat JSON` (one JSON object per
line, for example /var/log/modsec_audit.log). The log is only read, never changed.

With --state FILE the tool remembers how far it got, so each run sends only new lines. A half-written
last line waits for the next run; a rotated or truncated log is detected and read from the start.
Even without --state nothing is stored twice (event ids come from ModSec transaction ids).

Exit code 0 = no problems, 1 = some events failed, 2 = bad usage or configuration. --dry-run prints
the events (one JSON per line), sends nothing, saves nothing and needs no API key. The run stops at
once if the key is rejected, the API cannot be reached, a request times out or the API answers 5xx;
that line is retried next time. A rejected event (4xx such as 422) is counted as failed and skipped.
"""
import argparse
import hashlib
import json
import os
import sys

from integrations.client import ApiAuthError, IntegrationError
from integrations.cli_common import connect, positive_int
from integrations.config import load_settings
from integrations.modsec_parser import RecordSkipped, build_event

MAX_LINE = 1024 * 1024
HEAD_BYTES = 256
DEFAULT_MAX_EVENTS = 1000


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="modsec_adapter", description=__doc__.split("\n\n")[0])
    parser.add_argument("log", help="ModSecurity JSON audit log (read-only)")
    parser.add_argument("--state", help="file that remembers how far the log has been read")
    parser.add_argument("--max-events", type=positive_int, default=DEFAULT_MAX_EVENTS,
                        help=f"send at most this many events per run (default {DEFAULT_MAX_EVENTS})")
    parser.add_argument("--dry-run", action="store_true", help="print the events, send nothing")
    return parser


# ---- remembering the position ------------------------------------------------------------------

def _head_hash(handle, length: int) -> str:
    handle.seek(0)
    return hashlib.sha256(handle.read(length)).hexdigest()


def _load_offset(state_path, handle, size: int) -> int:
    """Where to resume. Anything doubtful (no/corrupt state, log shorter than the saved position,
    different beginning = rotated log) means start from the beginning."""
    try:
        with open(state_path, "r", encoding="utf-8") as state_file:
            state = json.load(state_file)
        offset, length, digest = state["offset"], state["head_length"], state["head_hash"]
        valid = (all(isinstance(v, int) and not isinstance(v, bool) for v in (offset, length))
                 and isinstance(digest, str) and 0 <= length <= min(HEAD_BYTES, offset) and 0 <= offset <= size)
        return offset if valid and _head_hash(handle, length) == digest else 0
    except (OSError, ValueError, KeyError, TypeError):
        return 0


def _save_offset(state_path, handle, offset: int) -> None:
    length = min(HEAD_BYTES, offset)
    state = {"offset": offset, "head_length": length, "head_hash": _head_hash(handle, length)}
    temporary = f"{state_path}.tmp"
    with open(temporary, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file)
    os.replace(temporary, state_path)      # atomic: a crash never leaves a half-written state file


# ---- reading lines --------------------------------------------------------------------------------

def _read_records(handle, stats):
    """Yield (record_or_None, end_offset) for every non-blank line, in order. None means the line is
    unusable (counted as invalid). A last line without a newline is used only if it is complete JSON;
    otherwise reading stops before it, so it is retried next run."""
    while True:
        raw = handle.readline(MAX_LINE + 1)
        if not raw:
            return
        complete = raw.endswith(b"\n")
        if len(raw) > MAX_LINE and not complete:
            while (rest := handle.readline(65536)) and not rest.endswith(b"\n"):
                pass
            yield None, handle.tell()
            continue
        text = raw.decode("utf-8", "replace").replace("﻿", "").strip()
        if not text:
            yield "blank", handle.tell()
            continue
        try:
            record = json.loads(text)
        except (ValueError, RecursionError):
            if not complete:
                stats["incomplete"] = 1
                return
            record = None
        yield (record if isinstance(record, dict) else None), handle.tell()


# ---- the run -------------------------------------------------------------------------------------------

def main(argv=None, *, client=None, settings_loader=load_settings) -> int:
    args = _parser().parse_args(argv)
    if not os.path.isfile(args.log):
        print("error: log file not found (or not a file)", file=sys.stderr)
        return 2
    owned = False
    if not args.dry_run and client is None:
        client = connect(settings_loader)
        if client is None:
            return 2
        owned = True
    try:
        return _run(args, client)
    except OSError:
        print("error: the log file could not be read", file=sys.stderr)
        return 2
    finally:
        if owned:
            client.close()


def _run(args, client) -> int:
    stats = {"read": 0, "stored": 0, "duplicate": 0, "failed": 0, "no_hits": 0, "invalid": 0, "incomplete": 0}
    sent, line_number, stopped_at_limit, aborted = 0, 0, False, False
    with open(args.log, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        offset = _load_offset(args.state, handle, size) if args.state else 0
        handle.seek(offset)
        for record, end in _read_records(handle, stats):
            line_number += 1
            if record == "blank":
                offset = end
                continue
            if sent >= args.max_events:
                stopped_at_limit = True
                break
            stats["read"] += 1
            event = None
            if record is None:
                stats["invalid"] += 1
            else:
                try:
                    event = build_event(record)
                except RecordSkipped as skip:
                    stats["no_hits" if skip.benign else "invalid"] += 1
                except Exception as exc:  # noqa: BLE001 - one hostile line must never end the run
                    stats["invalid"] += 1
                    print(f"line {line_number} of this run: unexpected {type(exc).__name__}, skipped",
                          file=sys.stderr)
            if event is not None:
                sent += 1
                if args.dry_run:
                    print(json.dumps(event, default=lambda value: value.isoformat()))
                    stats["stored"] += 1
                else:
                    try:
                        result = client.submit_event(event)
                    except ApiAuthError:
                        print("the API rejected the API key; check INGEST_API_KEY. Stopping.", file=sys.stderr)
                        stats["failed"] += 1
                        aborted = True
                        break
                    except IntegrationError as exc:
                        stats["failed"] += 1
                        if exc.retryable:      # connection, timeout, 5xx: stop before `offset = end` so the line is retried
                            print(f"{exc}. Stopping.", file=sys.stderr)
                            aborted = True
                            break
                        print(f"line {line_number} of this run: failed - {exc}", file=sys.stderr)
                    else:
                        stats["stored" if result.created else "duplicate"] += 1
            offset = end
        state_problem = False
        if args.state and not args.dry_run:
            try:
                _save_offset(args.state, handle, offset)
            except OSError:
                print("warning: could not save the state file; the next run will re-send (harmlessly)",
                      file=sys.stderr)
                state_problem = True

    summary = f"{args.log}: read {stats['read']} record(s): "
    summary += (f"{stats['stored']} event(s) printed" if args.dry_run else
                f"stored {stats['stored']}, already recorded {stats['duplicate']}, failed {stats['failed']}")
    summary += f"; no rule hits {stats['no_hits']}; invalid {stats['invalid']}."
    if stats["incomplete"]:
        summary += " Last line is incomplete and will be read next run."
    if stopped_at_limit:
        summary += f" Run stopped after {sent} events (--max-events); run again to continue."
    if aborted:
        summary += " Run aborted."
    print(summary)
    return 1 if stats["failed"] or state_problem else 0


if __name__ == "__main__":
    sys.exit(main())
