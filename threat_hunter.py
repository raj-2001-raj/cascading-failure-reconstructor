"""
Threat Hunting Module.

Runs SQL-based pattern matching for three common attack signatures:

  OVERSIZED_PATH     — URL longer than PATH_LENGTH_THRESHOLD chars; classic
                       indicator of buffer-overflow probing.

  BRUTE_FORCE        — IP with >= BRUTE_FORCE_THRESHOLD consecutive 401 errors
                       followed by a 200 OK, indicating a successful credential-
                       stuffing attempt.

  PATH_TRAVERSAL     — URL containing directory-hopping sequences or well-known
                       sensitive file paths (../../etc/passwd, etc.).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import List, Dict

PATH_LENGTH_THRESHOLD = 500
BRUTE_FORCE_THRESHOLD = 10


@dataclass
class ThreatFinding:
    threat_type: str
    ip: str
    detail: str
    evidence: List[dict] = field(default_factory=list)


def hunt_oversized_paths(
    conn: sqlite3.Connection,
    threshold: int = PATH_LENGTH_THRESHOLD,
) -> List[ThreatFinding]:
    """Flag requests where the URL path exceeds `threshold` characters."""
    rows = conn.execute(
        """
        SELECT ip, method, path, ts, length(path) AS path_len
        FROM   logs
        WHERE  length(path) > ?
        ORDER  BY path_len DESC
        LIMIT  20
        """,
        (threshold,),
    ).fetchall()

    findings = []
    for r in rows:
        findings.append(ThreatFinding(
            threat_type="OVERSIZED_PATH",
            ip=r["ip"],
            detail=(
                f"Path length {r['path_len']} chars — "
                f"{r['method']} {r['path'][:80]}{'...' if len(r['path']) > 80 else ''}"
                f" at {r['ts'] or 'unknown time'}"
            ),
        ))
    return findings


def hunt_brute_force(
    conn: sqlite3.Connection,
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> List[ThreatFinding]:
    """
    Find IPs that accumulated >= `threshold` 401 errors and subsequently
    received a 200 OK — the hallmark of a successful credential-stuffing run.
    The 200 must arrive after the last recorded 401 for that IP.
    """
    rows = conn.execute(
        """
        WITH auth_failures AS (
            SELECT  ip,
                    COUNT(*)     AS fail_count,
                    MAX(epoch_ms) AS last_fail_ms
            FROM    logs
            WHERE   status = 401
              AND   epoch_ms IS NOT NULL
            GROUP   BY ip
            HAVING  COUNT(*) >= ?
        ),
        success_after AS (
            SELECT  l.ip, l.ts, l.path, l.epoch_ms
            FROM    logs l
            JOIN    auth_failures af ON l.ip = af.ip
            WHERE   l.status = 200
              AND   l.epoch_ms IS NOT NULL
              AND   l.epoch_ms > af.last_fail_ms
        )
        SELECT  af.ip,
                af.fail_count,
                s.ts   AS success_ts,
                s.path AS success_path
        FROM    auth_failures af
        JOIN    success_after s ON af.ip = s.ip
        ORDER   BY af.fail_count DESC
        """,
        (threshold,),
    ).fetchall()

    findings = []
    seen_ips = set()
    for r in rows:
        if r["ip"] in seen_ips:
            continue
        seen_ips.add(r["ip"])
        findings.append(ThreatFinding(
            threat_type="BRUTE_FORCE",
            ip=r["ip"],
            detail=(
                f"{r['fail_count']} auth failures followed by successful login "
                f"at {r['success_ts'] or 'unknown time'} on {r['success_path']}"
            ),
        ))
    return findings


def hunt_path_traversal(conn: sqlite3.Connection) -> List[ThreatFinding]:
    """Flag requests whose URL contains directory-traversal or sensitive-file patterns."""
    rows = conn.execute(
        """
        SELECT ip, method, path, ts, status
        FROM   logs
        WHERE  path LIKE '%../%'
          OR   path LIKE '%..\\%'
          OR   path LIKE '%/etc/passwd%'
          OR   path LIKE '%/etc/shadow%'
          OR   path LIKE '%/proc/self%'
          OR   path LIKE '%/windows/system32%'
          OR   path LIKE '%/.env%'
          OR   path LIKE '%/wp-admin%'
        ORDER  BY ts
        LIMIT  50
        """,
    ).fetchall()

    findings = []
    for r in rows:
        findings.append(ThreatFinding(
            threat_type="PATH_TRAVERSAL",
            ip=r["ip"],
            detail=(
                f"{r['method']} {r['path']} → {r['status']} "
                f"at {r['ts'] or 'unknown time'}"
            ),
        ))
    return findings


def hunt_all(conn: sqlite3.Connection) -> Dict[str, List[ThreatFinding]]:
    return {
        "oversized_paths": hunt_oversized_paths(conn),
        "brute_force": hunt_brute_force(conn),
        "path_traversal": hunt_path_traversal(conn),
    }
