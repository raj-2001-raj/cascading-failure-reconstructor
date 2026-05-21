"""
Cascading Failure Reconstructor.

For every 5xx error, uses SQL LAG() window functions to pull the N preceding
requests from the same IP in true chronological order (by epoch_ms, not row
insertion order, so out-of-order log writes don't corrupt the timeline).

The number of lookback steps is configurable at call time; the SQL CTE is
built dynamically so there is no hardcoded limit.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CrashEvent:
    crash_id: int
    crash_ts: Optional[str]
    ip: str
    crash_method: str
    crash_path: str
    crash_status: int
    preceding: List[dict]   # ordered oldest → newest, ending just before crash


def _build_query(lookback: int) -> str:
    """
    Generates the LAG CTE dynamically for the requested lookback depth.
    Each LAG column group captures: id, ts, method, path, status, response_ms.
    """
    lag_cols = []
    for n in range(1, lookback + 1):
        lag_cols.append(f"""
            LAG(r.id,          {n}) OVER w AS prev{n}_id,
            LAG(r.ts,          {n}) OVER w AS prev{n}_ts,
            LAG(r.method,      {n}) OVER w AS prev{n}_method,
            LAG(r.path,        {n}) OVER w AS prev{n}_path,
            LAG(r.status,      {n}) OVER w AS prev{n}_status,
            LAG(r.response_ms, {n}) OVER w AS prev{n}_ms""")

    lag_sql = ",\n".join(lag_cols)

    return f"""
    WITH ranked AS (
        SELECT id, ts, epoch_ms, ip, method, path, status, response_ms
        FROM logs
        WHERE status IS NOT NULL
    ),
    with_history AS (
        SELECT
            r.id, r.ts, r.epoch_ms, r.ip, r.method, r.path, r.status, r.response_ms,
            {lag_sql}
        FROM ranked r
        WINDOW w AS (PARTITION BY ip ORDER BY epoch_ms NULLS LAST, id)
    )
    SELECT * FROM with_history
    WHERE status >= 500
    ORDER BY epoch_ms NULLS LAST, id
    """


def reconstruct(conn: sqlite3.Connection, lookback: int = 5) -> List[CrashEvent]:
    """
    Return one CrashEvent per 5xx row, each populated with up to `lookback`
    preceding requests from the same IP address.
    """
    query = _build_query(lookback)
    events: List[CrashEvent] = []

    for row in conn.execute(query):
        preceding = []
        for n in range(lookback, 0, -1):   # iterate oldest-first
            pid = row[f"prev{n}_id"]
            if pid is not None:
                preceding.append({
                    "id":          pid,
                    "ts":          row[f"prev{n}_ts"],
                    "method":      row[f"prev{n}_method"],
                    "path":        row[f"prev{n}_path"],
                    "status":      row[f"prev{n}_status"],
                    "response_ms": row[f"prev{n}_ms"],
                })

        events.append(CrashEvent(
            crash_id=row["id"],
            crash_ts=row["ts"],
            ip=row["ip"],
            crash_method=row["method"],
            crash_path=row["path"],
            crash_status=row["status"],
            preceding=preceding,
        ))

    return events
