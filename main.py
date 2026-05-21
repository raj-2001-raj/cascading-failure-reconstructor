#!/usr/bin/env python3
"""
Cascading Failure Reconstructor — CLI entry point.

Usage:
    python3 main.py <log_file> [options]

Examples:
    python3 main.py server.log
    python3 main.py server.log --lookback 10
    python3 main.py server.log --no-threats
    python3 main.py server.log --ai-analysis          # requires ANTHROPIC_API_KEY
"""

import argparse
import os
import sys

from db import build_db
from reconstructor import reconstruct
from reporter import print_summary, print_crash_timelines, print_threats
from threat_hunter import hunt_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Reconstruct the user journey leading to every server crash.",
    )
    p.add_argument(
        "log_file",
        metavar="LOG_FILE",
        help="Path to the server log file to analyze.",
    )
    p.add_argument(
        "--lookback",
        type=int,
        default=5,
        metavar="N",
        help="Requests to show before each crash (default: 5).",
    )
    p.add_argument(
        "--threats",
        dest="threats",
        action="store_true",
        default=True,
        help="Run threat-hunting queries (default: on).",
    )
    p.add_argument(
        "--no-threats",
        dest="threats",
        action="store_false",
        help="Skip threat-hunting queries.",
    )
    p.add_argument(
        "--ai-analysis",
        action="store_true",
        default=False,
        help=(
            "Send each crash timeline to Claude for a root-cause hypothesis. "
            "Requires ANTHROPIC_API_KEY and 'pip install anthropic'."
        ),
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.lookback < 1:
        print("Error: --lookback must be at least 1.", file=sys.stderr)
        return 1

    ai_client = None
    if args.ai_analysis:
        from analyzer import create_client
        ai_client = create_client()
        if ai_client is None:
            print(
                "Warning: --ai-analysis requested but ANTHROPIC_API_KEY is not set "
                "or 'anthropic' package is not installed. Skipping AI analysis.",
                file=sys.stderr,
            )

    db_path = None
    try:
        conn, stats, db_path = build_db(args.log_file)

        print_summary(conn, stats)

        events = reconstruct(conn, lookback=args.lookback)

        if ai_client is not None:
            from analyzer import analyze_crash
            for evt in events:
                evt.hypothesis = analyze_crash(evt, ai_client)
        else:
            for evt in events:
                evt.hypothesis = None

        print_crash_timelines(events)

        if args.threats:
            findings = hunt_all(conn)
            print_threats(findings)

        conn.close()

    except FileNotFoundError:
        print(f"Error: file not found — {args.log_file}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: permission denied — {args.log_file}", file=sys.stderr)
        return 1
    finally:
        if db_path and os.path.exists(db_path):
            os.unlink(db_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
