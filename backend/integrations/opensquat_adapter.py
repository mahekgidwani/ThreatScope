"""Command line: look for domains that resemble brand keywords and send `domain` events.

    python -m integrations.opensquat_adapter (--keywords FILE | --keyword WORD)... --domains FILE
        [--trusted FILE] [--confidence 0-4] [--max-events N] [--dry-run]

--domains is a text file with one domain per line (for example a newly-registered-domains feed);
'#' lines are comments. The file is read line by line, so big feeds are fine. A finding means a
domain NAME resembles a keyword, nothing more. Exit code 0 = no problems, 1 = some events
failed, 2 = bad usage or configuration. `--dry-run` prints the events (one JSON per line) and
needs no API key. The tool stops at once if the key is rejected or the API cannot be reached.
"""
import argparse
import json
import sys
from itertools import islice

from integrations.client import (
    ApiAuthError, ApiConnectionError, ApiTimeoutError, IntegrationError,
)
from integrations.cli_common import connect, positive_int
from integrations.config import load_settings
from integrations.opensquat_detector import build_event, clean_keyword, find_squatting, prepare_domain

MAX_LINE = 1024          # a longer line cannot be a domain or keyword; it is skipped without being loaded
DEFAULT_MAX_EVENTS = 500


def _confidence(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if not 0 <= value <= 4:
        raise argparse.ArgumentTypeError("must be a whole number from 0 (very high) to 4 (very low)")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opensquat_adapter", description=__doc__.split("\n\n")[0])
    parser.add_argument("--keywords", help="file with one brand keyword per line")
    parser.add_argument("--keyword", action="append", default=[], help="a keyword (can be repeated)")
    parser.add_argument("--domains", required=True, help="file with one domain per line")
    parser.add_argument("--trusted", help="file of domains to skip (the brand's own domains)")
    parser.add_argument("--confidence", type=_confidence, default=1,
                        help="0 (very high) .. 4 (very low); larger = more, weaker findings (default 1)")
    parser.add_argument("--max-events", type=positive_int, default=DEFAULT_MAX_EVENTS,
                        help=f"stop after this many findings (default {DEFAULT_MAX_EVENTS})")
    parser.add_argument("--dry-run", action="store_true", help="print the events, send nothing")
    return parser


def iter_lines(path):
    """Stripped lines of a text file. A line longer than MAX_LINE (or undecodable text) is
    yielded as None, and the rest of an over-long line is skipped without being held in memory."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        while line := handle.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE and not line.endswith("\n"):
                while (rest := handle.readline(65536)) and not rest.endswith("\n"):
                    pass
                yield None
            else:
                yield line.strip()


def _load_keywords(args) -> list[str] | str:
    lines = list(args.keyword)
    if args.keywords:
        try:
            lines += [line or "" for line in iter_lines(args.keywords)]
        except OSError:
            return "keywords file not found or unreadable"
    keywords = list(dict.fromkeys(k for k in map(clean_keyword, lines) if k))
    return keywords or "no valid keywords (3-63 characters, no spaces or dots)"


def _load_trusted(path) -> set[str] | str:
    try:
        return {d for d in map(prepare_domain, (line or "" for line in iter_lines(path))) if d}
    except OSError:
        return "trusted file not found or unreadable"


def main(argv=None, *, client=None, settings_loader=load_settings) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.keywords and not args.keyword:
        parser.error("give at least one keyword with --keyword or --keywords")
    keywords = _load_keywords(args)
    trusted = _load_trusted(args.trusted) if args.trusted else set()
    for problem in (keywords, trusted):
        if isinstance(problem, str):
            print(f"error: {problem}", file=sys.stderr)
            return 2
    try:
        open(args.domains, "rb").close()
    except OSError:
        print("error: domains file not found or unreadable", file=sys.stderr)
        return 2

    owned = False
    if not args.dry_run and client is None:
        client = connect(settings_loader)
        if client is None:
            return 2
        owned = True
    try:
        return _run(args, keywords, trusted, client)
    finally:
        if owned:
            client.close()


def _run(args, keywords, trusted, client) -> int:
    stats = {"domains": 0, "invalid": 0, "stored": 0, "duplicate": 0, "failed": 0}

    def domains():
        for line in iter_lines(args.domains):
            if line is not None and (line == "" or line.startswith("#")):
                continue
            domain = prepare_domain(line) if line is not None else None
            if domain is None:
                stats["invalid"] += 1
            else:
                stats["domains"] += 1
                yield domain

    found = list(islice(find_squatting(keywords, domains(), args.confidence, trusted), args.max_events + 1))
    stopped_at_limit = len(found) > args.max_events
    found = found[:args.max_events]

    aborted = False
    for finding in found:
        event = build_event(finding)
        if args.dry_run:
            print(json.dumps(event, default=lambda value: value.isoformat()))
            continue
        try:
            result = client.submit_event(event)
        except ApiAuthError:
            print("the API rejected the API key; check INGEST_API_KEY. Stopping.", file=sys.stderr)
            aborted = True
            stats["failed"] += 1
            break
        except (ApiConnectionError, ApiTimeoutError) as exc:
            print(f"{exc}. Stopping.", file=sys.stderr)
            aborted = True
            stats["failed"] += 1
            break
        except IntegrationError as exc:
            print(f"{finding.domain}: failed - {exc}", file=sys.stderr)
            stats["failed"] += 1
        else:
            stats["stored" if result.created else "duplicate"] += 1
            verb = "stored as" if result.created else "already recorded as"
            print(f"{finding.domain}: {finding.keyword} ({finding.kind}) {verb} {result.event_id}")

    summary = (f"Checked {stats['domains']} domain(s) against {len(keywords)} keyword(s): "
               f"{len(found)} finding(s)")
    if not args.dry_run:
        summary += (f"; stored {stats['stored']}, already recorded {stats['duplicate']}, "
                    f"failed {stats['failed']}")
    summary += f"; skipped {stats['invalid']} invalid line(s)."
    if stopped_at_limit:
        summary += f" Run stopped after {args.max_events} findings (--max-events); more may exist."
    if aborted:
        summary += " Run aborted."
    print(summary)
    return 1 if stats["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
