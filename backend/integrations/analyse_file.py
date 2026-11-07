"""Command line: statically analyse files and send one `file` event each to ThreatScope.

    python -m integrations.analyse_file PATH [PATH ...] [--max-bytes N] [--dry-run]

Exit code 0 = every file analysed and stored (or already recorded); 1 = at least one problem;
2 = bad usage or configuration. `--dry-run` prints the event instead of sending it and needs no
API key. The tool prints names, types and ids only - never file contents.
"""
import argparse
import json
import sys

from integrations.client import ApiAuthError, IntegrationError
from integrations.cli_common import connect
from integrations.config import load_settings
from integrations.file_analyser import (
    DEFAULT_MAX_BYTES, FileAnalysisError, analyse_file, build_event, printable,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="analyse_file", description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", help="files to analyse (never executed)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"refuse bigger files (default {DEFAULT_MAX_BYTES})")
    parser.add_argument("--dry-run", action="store_true", help="print the event, do not send it")
    return parser


def main(argv=None, *, client=None, settings_loader=load_settings) -> int:
    args = _parser().parse_args(argv)
    owned = False
    if not args.dry_run and client is None:
        client = connect(settings_loader)
        if client is None:
            return 2
        owned = True
    try:
        return _run(args, client)
    finally:
        if owned:
            client.close()


def _run(args, client) -> int:
    failures = 0
    for raw in args.paths:
        label = printable(str(raw), 200)
        try:
            event = build_event(analyse_file(raw, max_bytes=args.max_bytes))
            if args.dry_run:
                print(json.dumps(event, indent=2, default=lambda value: value.isoformat()))
                continue
            result = client.submit_event(event)
        except FileAnalysisError as exc:
            print(f"{label}: skipped - {exc}", file=sys.stderr)
            failures += 1
        except ApiAuthError:
            print(f"{label}: the API rejected the API key; check INGEST_API_KEY. Stopping.", file=sys.stderr)
            return 1
        except IntegrationError as exc:
            print(f"{label}: failed - {exc}", file=sys.stderr)
            failures += 1
        else:
            markers = len(event["metadata"]["review_markers"])
            verb = "stored as" if result.created else "already recorded as"
            print(f"{label}: {verb} {result.event_id} "
                  f"({event['metadata']['detected_type']}, {markers} review marker(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
