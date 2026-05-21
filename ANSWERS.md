# ANSWERS.md

## 1. How to run

Prerequisites: Python 3.8+ — no third-party packages needed.

```bash
# Step 1 — generate a test log
python3 scripts/generate_logs.py sample.log --lines 2000

# Step 2 — run the tool
python3 main.py sample.log

# Optional: increase the lookback window (default is 5)
python3 main.py sample.log --lookback 10

# Show help
python3 main.py --help
```

The tool accepts any file path. It does not assume specific filenames, line counts, or fixed IP/path values.

---

## 2. Stack choice

**Python 3 + disk-backed SQLite** — both are part of the standard library. No `pip install` is needed; the tool runs on any stock Python installation.

**Why SQLite specifically:** The crash reconstruction step requires "find all requests by IP X that appeared before row Y, ordered by real timestamp." That is exactly what SQL window functions (`LAG()`, `PARTITION BY`, `ORDER BY`) are designed for. Writing equivalent logic in pure Python requires maintaining a growing per-IP deque and scanning it on every 5xx hit — O(n·k) and hard to read. SQLite does it in a single indexed pass.

**Why disk-backed, not `:memory:`:** An in-memory SQLite database loads the entire working set into RAM. A 10 GB production log would exhaust available memory before producing a single line of output. The tool uses `tempfile.NamedTemporaryFile` to create a SQLite file on disk, which the OS pages in and out as needed. The temp file is deleted in a `finally` block so it is never left behind, even on error.

**What would have been a worse choice:**

- **Pandas** — `DataFrame.groupby().shift()` looks elegant for small files but loads everything into RAM. A 10 GB log causes an OOM kill before any output appears.
- **grep/awk pipeline** — can count errors but cannot reconstruct per-IP timelines across arbitrarily large files without multiple passes and fragile shell state.

---

## 3. One real edge case

**File:** [parser.py](parser.py), **line 131**

```python
status = int(status_raw) if status_raw and status_raw != "-" else None
```

The log spec says status codes may be replaced with a literal `-`. Without this guard, three failures cascade:

1. `int("-")` raises `ValueError`, crashing the ingestion loop for the entire file.
2. Even with a `try/except`, storing `"-"` as a string in the `status INTEGER` column corrupts every numeric comparison (`WHERE status >= 500` would silently exclude the row).
3. Dropping the row entirely would undercount requests, skew the summary statistics, and hide a crash that happened to arrive with a missing status field.

With the `None` path, the row is inserted cleanly (`NULL` in SQLite), counted as parsed, and excluded only from status-specific queries. No data is silently lost.

---

## 4. AI usage

**Tool used:** Claude (claude-sonnet-4-6) throughout this session.

| What I asked for | What it gave me | What I changed and why |
|---|---|---|
| Overall architecture | Suggested a Python deque-per-IP state tracker | Switched to SQL `LAG()` window functions — the deque approach requires rescanning the history dict on every 5xx hit and grows unbounded in memory for long log files |
| Regex for the multi-format parser | A single `_PRIMARY` pattern with `\S+` for the timestamp | Added a two-token `(?:\s+\S+)?` capture and a dedicated `_parse_timestamp()` dispatcher, because `15-Mar-2024 14:23:01` contains a space that `\S+` would split across two fields |
| The `_try_json()` function | Used direct key access (`obj["ip"]`) that raises `KeyError` on missing fields | Replaced with `.get()` and fallback key aliases (`"remote_addr"`, `"client"`) and added a guard requiring both `ip` and `status` before accepting the line |
| Type annotations | Used `X \| None` union syntax (Python 3.10+) | Replaced with `Optional[X]` from `typing` and added `from __future__ import annotations` for forward-reference safety, since the target machine may run Python 3.8 or 3.9 |
| Initial CLI | Used `sys.argv[1]` direct indexing | Replaced with `argparse` to get `--help`, type validation, and the `--lookback N` flag without manual parsing |

---

## 5. Honest gap

**The `epoch_ms` column is `NULL` for lines where timestamp parsing fails**, which affects sort order. When a log line has an unparseable timestamp (e.g., a partial write like `2024-03-15T14`), `epoch_ms` is stored as `NULL`. The window function uses `ORDER BY epoch_ms NULLS LAST, id` as a fallback, so these rows sort after all timestamped rows for that IP rather than in their true position.

**What I would fix with another day:** Add a second parsing pass that infers a timestamp from surrounding lines with the same IP address — if a row with `NULL` epoch appears between two rows at `t=1000ms` and `t=1200ms`, assign it `t=1100ms` as a reasonable midpoint. This would eliminate the NULLS LAST fallback and make the timeline accurate even for partially-written log lines.
