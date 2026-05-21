"""
SQLite ingestion layer.

Uses a temporary disk file (not :memory:) so the tool survives log files
larger than available RAM.  The caller receives the temp file path and is
responsible for deleting it after the connection is closed.
"""

import sqlite3
import tempfile
from typing import Tuple, Dict

from parser import parse_line


def build_db(log_path: str) -> Tuple[sqlite3.Connection, Dict, str]:
    """
    Read log_path line by line, parse, and insert into a disk-backed SQLite db.

    Returns (connection, stats, db_path).  The caller must delete db_path after
    closing the connection — using tempfile on disk prevents OOM on large files.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_path = tmp.name

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT,
            epoch_ms      REAL,       -- Unix ms; used for chronological ORDER BY
            ip            TEXT NOT NULL,
            method        TEXT,
            path          TEXT,
            status        INTEGER,    -- NULL when source line had '-'
            response_ms   REAL,
            raw           TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX idx_ip_epoch ON logs (ip, epoch_ms)")

    stats = {"total": 0, "parsed": 0, "skipped": 0}

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            stats["total"] += 1
            entry = parse_line(line)
            if entry is None or entry.get("ip") is None:
                stats["skipped"] += 1
                continue

            ts_str = entry["timestamp"].isoformat() if entry["timestamp"] else None
            conn.execute(
                "INSERT INTO logs "
                "(ts, epoch_ms, ip, method, path, status, response_ms, raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts_str,
                    entry.get("epoch_ms"),
                    entry["ip"],
                    entry.get("method"),
                    entry.get("path"),
                    entry.get("status"),
                    entry.get("response_ms"),
                    entry["raw"].strip(),
                ),
            )
            stats["parsed"] += 1

    conn.commit()
    return conn, stats, db_path
