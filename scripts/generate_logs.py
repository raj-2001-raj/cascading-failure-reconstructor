#!/usr/bin/env python3
"""
Generates a synthetic log file for testing the Cascading Failure Reconstructor.

Usage:
    python3 scripts/generate_logs.py [output_path] [--lines N]

Defaults:
    output_path = sample.log
    lines       = 2000
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

PATHS = [
    "/api/users", "/api/users/12", "/api/users/99",
    "/api/login", "/api/logout", "/api/settings",
    "/api/export_large_report", "/api/download",
    "/api/orders", "/api/orders/55", "/api/search",
    "/health", "/static/app.js", "/static/style.css",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
METHOD_WEIGHTS = [60, 20, 8, 5, 7]

IPS = [
    "192.168.1.42", "192.168.1.77", "10.0.0.7",
    "10.0.0.99", "172.16.0.5", "203.0.113.10",
]

STATUS_POOL = (
    [200] * 70 + [201] * 5 + [204] * 3 +
    [301] * 2 + [304] * 5 +
    [400] * 4 + [401] * 3 + [403] * 2 + [404] * 4 +
    [500] * 1 + [502] * 1 + [503] * 1
)

USER_AGENTS = [
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '"curl/7.68.0"',
    '"python-requests/2.28.0"',
]

MALFORMED_LINES = [
    "",
    "   ",
    "WARN: disk usage above 80%",
    "Exception in thread main java.lang.NullPointerException",
    "\tat com.example.App.run(App.java:42)",
    "2024-03-15T14:23:01Z PARTIAL LOG WRITE",
    "not a log line at all",
    "{bad json: [}",
]


def fmt_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def fmt_slash(dt: datetime) -> str:
    return dt.strftime("%Y/%m/%d %H:%M:%S")

def fmt_day_mon(dt: datetime) -> str:
    return dt.strftime("%d-%b-%Y %H:%M:%S")

def fmt_epoch(dt: datetime) -> str:
    return str(int(dt.timestamp()))

TS_FORMATTERS = [fmt_iso, fmt_iso, fmt_iso, fmt_iso, fmt_slash, fmt_day_mon, fmt_epoch]


def fmt_response(ms: int) -> str:
    choice = random.randint(0, 2)
    if choice == 0:
        return f"{ms}ms"
    if choice == 1:
        return f"{ms / 1000:.3f}s"
    return str(ms)


def normal_line(dt, ip, method, path, status, ms) -> str:
    ts = random.choice(TS_FORMATTERS)(dt)
    line = f"{ts} {ip} {method} {path} {status} {fmt_response(ms)}"
    if random.random() < 0.10:
        line += f" {random.choice(USER_AGENTS)}"
    if random.random() < 0.05:
        line += ' "https://example.com/referrer page"'
    return line


def json_line(dt, ip, method, path, status, ms) -> str:
    return json.dumps({
        "timestamp": fmt_iso(dt),
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "response_time": f"{ms}ms",
    })


def missing_status_line(dt, ip, method, path, ms) -> str:
    return f"{fmt_iso(dt)} {ip} {method} {path} - {ms}ms"


def generate(output_path: Path, n_lines: int) -> None:
    start = datetime(2024, 3, 15, 14, 0, 0, tzinfo=timezone.utc)
    dt = start
    ip_session = {ip: random.choice(PATHS) for ip in IPS}
    lines = []
    crash_setup_ip = None
    crash_countdown = 0

    for i in range(n_lines):
        dt += timedelta(seconds=random.uniform(0.1, 2.0))
        ip = random.choice(IPS)
        method = random.choices(METHODS, METHOD_WEIGHTS)[0]
        path = ip_session.get(ip, random.choice(PATHS)) if random.random() < 0.6 else random.choice(PATHS)
        status = random.choice(STATUS_POOL)
        ms = random.randint(10, 3000)

        # Realistic crash pattern: export_large_report → download → 500
        if crash_countdown > 0 and ip == crash_setup_ip:
            crash_countdown -= 1
            if crash_countdown == 0:
                path = "/api/download"
                status = 500
                ms = random.randint(5000, 12000)

        if i % 200 == 199:
            crash_setup_ip = random.choice(IPS)
            crash_countdown = random.randint(2, 4)
            if ip == crash_setup_ip:
                path = "/api/export_large_report"

        roll = random.random()
        if roll < 0.03:
            lines.append(random.choice(MALFORMED_LINES))
            continue
        elif roll < 0.06:
            lines.append(json_line(dt, ip, method, path, status, ms))
            continue
        elif roll < 0.08:
            lines.append(missing_status_line(dt, ip, method, path, ms))
            continue

        lines.append(normal_line(dt, ip, method, path, status, ms))

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated {len(lines):,} lines → {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic log file")
    parser.add_argument("output", nargs="?", default="sample.log")
    parser.add_argument("--lines", type=int, default=2000)
    args = parser.parse_args()
    generate(Path(args.output), args.lines)


if __name__ == "__main__":
    main()
