"""
Log line parser supporting multiple formats and graceful degradation.
Returns structured dicts or None for lines that cannot be salvaged.
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from typing import Optional

_MONTH_ABBR = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_PRIMARY = re.compile(
    r"""
    (?P<timestamp>\S+(?:\s+\S+)?)              # timestamp (may contain one space)
    \s+
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})            # IPv4
    \s+
    (?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)
    \s+
    (?P<path>\S+)
    \s+
    (?P<status>\d{3}|-)
    \s+
    (?P<response_time>\d+(?:\.\d+)?(?:ms|s)?)  # 142ms | 0.142s | 142
    """,
    re.VERBOSE,
)


def _parse_timestamp(raw: str) -> Optional[datetime]:
    raw = raw.strip()

    # ISO 8601: 2024-03-15T14:23:01Z
    try:
        return datetime.fromisoformat(raw.rstrip("Z")).replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Slash: 2024/03/15 14:23:01
    try:
        return datetime.strptime(raw, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Day-Mon-Year: 15-Mar-2024 14:23:01
    m = re.match(r"(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})", raw)
    if m:
        day, mon, year, hh, mm, ss = m.groups()
        month_num = _MONTH_ABBR.get(mon.lower())
        if month_num:
            return datetime(
                int(year), month_num, int(day),
                int(hh), int(mm), int(ss), tzinfo=timezone.utc,
            )

    # Unix epoch (10-digit integer)
    if re.fullmatch(r"\d{9,11}", raw):
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)
        except (ValueError, OSError):
            pass

    return None


def _normalize_response_ms(raw: str) -> Optional[float]:
    raw = raw.strip()
    if raw.endswith("ms"):
        try:
            return float(raw[:-2])
        except ValueError:
            return None
    if raw.endswith("s"):
        try:
            return float(raw[:-1]) * 1000
        except ValueError:
            return None
    try:
        return float(raw)
    except ValueError:
        return None


def _try_json(line: str) -> Optional[dict]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(obj, dict):
        return None

    ts_raw = obj.get("timestamp") or obj.get("time") or obj.get("ts")
    ip = obj.get("ip") or obj.get("remote_addr") or obj.get("client")
    method = obj.get("method") or obj.get("http_method")
    path = obj.get("path") or obj.get("uri") or obj.get("url")
    status = obj.get("status") or obj.get("status_code") or obj.get("code")
    rt_raw = obj.get("response_time") or obj.get("latency") or obj.get("duration")

    if not (ip and status):
        return None

    ts = _parse_timestamp(str(ts_raw)) if ts_raw else None
    rt_ms = _normalize_response_ms(str(rt_raw)) if rt_raw else None

    return {
        "timestamp": ts,
        "epoch_ms": ts.timestamp() * 1000 if ts else None,
        "ip": str(ip),
        "method": str(method).upper() if method else "UNKNOWN",
        "path": str(path) if path else "/unknown",
        "status": int(status) if str(status).isdigit() else None,
        "response_ms": rt_ms,
        "raw": line,
    }


def parse_line(line: str) -> Optional[dict]:
    """
    Parse a single log line.  Returns None if the line is unsalvageable.

    Edge case at status check below: lines with a literal '-' status get
    status=None rather than crashing the SQL insert with a NOT NULL violation
    or corrupting numeric comparisons with a string value.
    """
    line = line.strip()
    if not line:
        return None

    json_result = _try_json(line)
    if json_result is not None:
        return json_result

    m = _PRIMARY.search(line)
    if not m:
        return None

    ts = _parse_timestamp(m.group("timestamp"))

    status_raw = m.group("status")
    status = int(status_raw) if status_raw and status_raw != "-" else None  # line 131

    rt_ms = _normalize_response_ms(m.group("response_time"))

    return {
        "timestamp": ts,
        "epoch_ms": ts.timestamp() * 1000 if ts else None,  # stored for reliable ORDER BY
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": status,
        "response_ms": rt_ms,
        "raw": line,
    }
