# Cascading Failure Reconstructor

A server-log analysis tool for on-call engineers. When a 5xx crash occurs, most tools count it. This tool rewinds the tape — it reconstructs the exact HTTP requests that user made **before** the crash, so you can reproduce the failure path in minutes.

---

## Base Tool — Zero Dependencies

The core CLI requires **nothing beyond a stock Python 3.8+ installation**. No `pip install`. No virtualenv. It works on any machine Python ships on.

### Step 1 — Generate a test log

```bash
python3 scripts/generate_logs.py sample.log --lines 2000
```

### Step 2 — Run the analysis

```bash
python3 main.py sample.log
```

That's it. You'll get:

- Parse summary (lines read / parsed / skipped)
- Status code breakdown
- Top 10 slowest endpoints
- Top 10 most error-prone paths
- Full crash timelines (who was doing what before each 5xx)
- Threat hunting report (buffer-overflow probes, brute force, path traversal)

### All CLI options

```bash
python3 main.py --help

python3 main.py sample.log                   # default: 5 requests before each crash
python3 main.py sample.log --lookback 10     # show 10 requests before each crash
python3 main.py sample.log --no-threats      # skip the threat-hunting section
```

---

## Advanced Features — Requires Pip

These features are **completely optional**. The base tool above works without them.

### AI Root-Cause Hypothesis

Sends each crash timeline to Claude Haiku, which writes a 2–3 sentence SRE hypothesis explaining *why* the crash likely happened.

```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
python3 main.py sample.log --ai-analysis
```

If the package is missing or the key is not set, the tool prints a warning and continues normally — it never crashes.

### Interactive Streamlit Dashboard

A browser-based UI with clickable crash timelines, a status-code bar chart, slowest-endpoint table, and threat-findings panel.

```bash
pip install streamlit pandas
streamlit run dashboard.py
```

Then open `http://localhost:8501` in your browser and upload any log file.

---

## Log Formats Handled

| Category | Variants |
|---|---|
| Timestamps | ISO 8601, `YYYY/MM/DD HH:MM:SS`, `DD-Mon-YYYY HH:MM:SS`, Unix epoch |
| Response time | `142ms`, `0.142s`, `142` (bare number — assumed ms) |
| Missing status | `-` stored as NULL; row is kept and counted, never dropped |
| JSON log lines | `{"timestamp":…, "ip":…, "status":…}` with key aliases |
| Extra trailing fields | User-agent strings, quoted referrers — silently ignored |
| Fully malformed lines | Counted and skipped; tool never crashes on bad input |

---

## Project Layout

```
.
├── main.py                 # CLI entry point (argparse, no pip deps)
├── parser.py               # Multi-format log line parser
├── db.py                   # Disk-backed SQLite ingestion (tempfile, not :memory:)
├── reconstructor.py        # SQL LAG() window-function crash timeline engine
├── reporter.py             # Human-readable terminal output
├── threat_hunter.py        # SQL-based threat detection queries
├── analyzer.py             # Claude API root-cause hypothesis (optional)
├── dashboard.py            # Streamlit browser UI (optional)
├── conftest.py             # pytest path setup
├── requirements.txt        # Optional pip deps (anthropic, streamlit, pandas)
├── scripts/
│   └── generate_logs.py    # Synthetic log generator (no pip deps)
├── tests/
│   └── test_parser.py      # 43 pytest unit tests
└── .github/
    └── workflows/
        └── test.yml         # CI: flake8 + pytest on Python 3.9 / 3.11 / 3.12
```

---

## Design Decisions

| Decision | Reason |
|---|---|
| Disk-backed SQLite (`tempfile`), not `:memory:` | Survives log files larger than available RAM |
| `ORDER BY epoch_ms` in window functions | True chronological order; not insertion order, so async log writes don't corrupt timelines |
| Dynamic `LAG()` CTE generation | `--lookback N` works for any N without hardcoded SQL |
| Lazy `import anthropic` inside functions | Core tool stays zero-dep; AI feature fails with a warning, not a crash |
