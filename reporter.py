"""Formats analysis results for human-readable terminal output."""

from __future__ import annotations

import sqlite3
from collections import Counter
from typing import Optional, List, Dict

from reconstructor import CrashEvent
from threat_hunter import ThreatFinding


def _fmt_ms(ms: Optional[float]) -> str:
    return f"{ms:.0f}ms" if ms is not None else "?ms"


def _ts_display(iso: Optional[str]) -> str:
    if iso and len(iso) >= 19:
        return iso[11:19]
    return "??:??:??"


def print_summary(conn: sqlite3.Connection, stats: dict) -> None:
    print("=" * 65)
    print("  SERVER LOG ANALYSIS — CASCADING FAILURE RECONSTRUCTOR")
    print("=" * 65)
    print(f"\n  Lines read   : {stats['total']:,}")
    print(f"  Lines parsed : {stats['parsed']:,}")
    print(f"  Lines skipped: {stats['skipped']:,}  (malformed / unrecognised)")

    total_reqs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    print(f"\n--- STATUS CODE BREAKDOWN ({total_reqs:,} requests with known status) ---\n")
    for r in conn.execute(
        "SELECT status, COUNT(*) c FROM logs WHERE status IS NOT NULL "
        "GROUP BY status ORDER BY status"
    ):
        bar = "#" * min(40, r["c"] // max(1, total_reqs // 400))
        print(f"  {r['status']}  {r['c']:>6,}  {bar}")

    print("\n--- TOP 10 SLOWEST ENDPOINTS (avg response time) ---\n")
    for r in conn.execute("""
        SELECT path, method, COUNT(*) hits,
               AVG(response_ms) avg_ms, MAX(response_ms) max_ms
        FROM logs
        WHERE response_ms IS NOT NULL
        GROUP BY path, method
        ORDER BY avg_ms DESC
        LIMIT 10
    """):
        print(
            f"  {r['method']:<7} {r['path']:<35} "
            f"avg={_fmt_ms(r['avg_ms'])}  max={_fmt_ms(r['max_ms'])}  hits={r['hits']}"
        )

    print("\n--- TOP 10 MOST ERRORING PATHS (5xx) ---\n")
    rows = conn.execute(
        "SELECT path, COUNT(*) c FROM logs WHERE status >= 500 "
        "GROUP BY path ORDER BY c DESC LIMIT 10"
    ).fetchall()
    if rows:
        for r in rows:
            print(f"  {r['c']:>5,}x  {r['path']}")
    else:
        print("  None found.")


def print_crash_timelines(events: List[CrashEvent]) -> None:
    if not events:
        print("\n  No 5xx server errors detected. System looks healthy.\n")
        return

    print(f"\n{'=' * 65}")
    print(f"  CRASH TIMELINES — {len(events)} server error(s) reconstructed")
    print(f"{'=' * 65}\n")

    for evt in events:
        print(f"  CRASH #{evt.crash_id}  [{evt.crash_status}]  at {evt.crash_ts or 'unknown time'}")
        print(f"  Offending IP : {evt.ip}")
        print(f"  Crashed on   : {evt.crash_method} {evt.crash_path}")
        print()

        if evt.preceding:
            print("  Journey leading to crash:")
            for i, req in enumerate(evt.preceding, 1):
                ts_str = _ts_display(req["ts"])
                print(
                    f"    {i}. [{ts_str}] "
                    f"{req['method']:<7} {req['path']:<35} "
                    f"{req['status']}  {_fmt_ms(req['response_ms'])}"
                )
        else:
            print("  (No preceding requests from this IP in the log window)")

        crash_ts = _ts_display(evt.crash_ts)
        print(f"  {'─' * 60}")
        print(
            f"  >>> [{crash_ts}] {evt.crash_method:<7} {evt.crash_path:<35} "
            f"{evt.crash_status}  CRASH"
        )

        hypothesis = getattr(evt, "hypothesis", None)
        if hypothesis:
            print()
            print("  AI Hypothesis:")
            for line in hypothesis.splitlines():
                print(f"    {line}")

        print()

    path_counter: Counter = Counter(e.crash_path for e in events)
    repeated = [(p, c) for p, c in path_counter.most_common() if c > 1]
    if repeated:
        print("--- RECURRING CRASH TRIGGERS (same path crashed multiple times) ---\n")
        for path, count in repeated:
            print(f"  {count:>4}x  {path}")
        print()


def print_threats(findings: Dict[str, List[ThreatFinding]]) -> None:
    total = sum(len(v) for v in findings.values())

    print(f"\n{'=' * 65}")
    print("  THREAT HUNTING REPORT")
    print(f"{'=' * 65}\n")

    if total == 0:
        print("  No threat indicators detected.\n")
        return

    labels = {
        "oversized_paths": "OVERSIZED PATH  (buffer-overflow probe indicator)",
        "brute_force":     "BRUTE FORCE     (credential stuffing)",
        "path_traversal":  "PATH TRAVERSAL  (directory hopping / file disclosure)",
    }

    for key, threat_list in findings.items():
        if not threat_list:
            continue
        print(f"  [{labels[key]}]  {len(threat_list)} finding(s)\n")
        for f in threat_list:
            print(f"    IP: {f.ip}")
            print(f"        {f.detail}")
            print()
