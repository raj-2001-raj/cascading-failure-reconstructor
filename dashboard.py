"""
Interactive Streamlit dashboard for the Cascading Failure Reconstructor.

Run with:
    streamlit run dashboard.py

Requires: streamlit, pandas  (pip install streamlit pandas)
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from db import build_db  # noqa: E402
from reconstructor import reconstruct  # noqa: E402
from threat_hunter import hunt_all  # noqa: E402

st.set_page_config(
    page_title="Cascading Failure Reconstructor",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 Cascading Failure Reconstructor")
st.caption("Upload a server log to reconstruct crash timelines and hunt for security threats.")

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Settings")
    uploaded = st.file_uploader("Upload log file", type=["log", "txt"])
    lookback = st.slider("Lookback window (requests before crash)", 1, 20, 5)
    show_threats = st.checkbox("Run threat hunting", value=True)
    st.divider()
    st.caption("Core tool needs no extra packages. Dashboard requires streamlit + pandas.")

if uploaded is None:
    st.info("Upload a log file in the sidebar to begin.")
    st.stop()

# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
tmp_log = tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="wb")
tmp_log.write(uploaded.read())
tmp_log.close()

db_path = None
try:
    with st.spinner("Parsing log file…"):
        conn, stats, db_path = build_db(tmp_log.name)

    # Ingestion metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Lines read", f"{stats['total']:,}")
    c2.metric("Lines parsed", f"{stats['parsed']:,}")
    c3.metric("Lines skipped", f"{stats['skipped']:,}", delta_color="inverse")

    # ---------------------------------------------------------------------------
    # Status code distribution
    # ---------------------------------------------------------------------------
    st.subheader("Status Code Distribution")
    status_rows = conn.execute(
        "SELECT status, COUNT(*) c FROM logs "
        "WHERE status IS NOT NULL GROUP BY status ORDER BY status"
    ).fetchall()

    if status_rows:
        df_status = pd.DataFrame(status_rows, columns=["Status", "Count"])
        df_status["Status"] = df_status["Status"].astype(str)

        col_chart, col_table = st.columns([2, 1])
        with col_chart:
            st.bar_chart(df_status.set_index("Status"))
        with col_table:
            st.dataframe(df_status, use_container_width=True, hide_index=True)

    # ---------------------------------------------------------------------------
    # Slowest endpoints
    # ---------------------------------------------------------------------------
    st.subheader("Top 10 Slowest Endpoints")
    slow_rows = conn.execute("""
        SELECT  method || ' ' || path  AS endpoint,
                ROUND(AVG(response_ms)) AS avg_ms,
                ROUND(MAX(response_ms)) AS max_ms,
                COUNT(*)               AS hits
        FROM    logs
        WHERE   response_ms IS NOT NULL
        GROUP   BY endpoint
        ORDER   BY avg_ms DESC
        LIMIT   10
    """).fetchall()

    if slow_rows:
        df_slow = pd.DataFrame(
            slow_rows, columns=["Endpoint", "Avg (ms)", "Max (ms)", "Hits"]
        )
        st.dataframe(df_slow, use_container_width=True, hide_index=True)

    # ---------------------------------------------------------------------------
    # Crash timelines
    # ---------------------------------------------------------------------------
    st.subheader("Crash Timelines")
    events = reconstruct(conn, lookback=lookback)

    if not events:
        st.success("No 5xx server errors detected in this log.")
    else:
        st.error(f"{len(events)} server error(s) detected")

        # Summary table of all crashes
        crash_summary = pd.DataFrame([{
            "ID": e.crash_id,
            "Time": e.crash_ts or "?",
            "IP": e.ip,
            "Method": e.crash_method,
            "Path": e.crash_path,
            "Status": e.crash_status,
        } for e in events])
        st.dataframe(crash_summary, use_container_width=True, hide_index=True)

        # Expandable detail per crash
        st.markdown("---")
        st.markdown("**Click a crash to see the full user journey:**")
        for evt in events:
            label = (
                f"[{evt.crash_status}] {evt.crash_method} {evt.crash_path}"
                f" — IP {evt.ip} — {evt.crash_ts or 'unknown time'}"
            )
            with st.expander(label):
                rows_data = []
                for req in evt.preceding:
                    rows_data.append({
                        "Time": (req["ts"] or "?")[11:19] if req["ts"] else "?",
                        "Method": req["method"],
                        "Path": req["path"],
                        "Status": req["status"],
                        "Response (ms)": (
                            int(req["response_ms"]) if req["response_ms"] else None
                        ),
                        "Event": "→",
                    })
                rows_data.append({
                    "Time": (evt.crash_ts or "?")[11:19] if evt.crash_ts else "?",
                    "Method": evt.crash_method,
                    "Path": evt.crash_path,
                    "Status": evt.crash_status,
                    "Response (ms)": None,
                    "Event": "💥 CRASH",
                })
                df_evt = pd.DataFrame(rows_data)
                st.dataframe(df_evt, use_container_width=True, hide_index=True)

    # ---------------------------------------------------------------------------
    # Threat hunting
    # ---------------------------------------------------------------------------
    if show_threats:
        st.subheader("Threat Hunting")
        with st.spinner("Scanning for attack signatures…"):
            threats = hunt_all(conn)

        total = sum(len(v) for v in threats.values())
        if total == 0:
            st.success("No threat indicators detected.")
        else:
            st.warning(f"{total} threat indicator(s) found")

            labels = {
                "oversized_paths": "Oversized Path (Buffer Overflow Probe)",
                "brute_force": "Brute Force / Credential Stuffing",
                "path_traversal": "Path Traversal Attempt",
            }
            for key, findings in threats.items():
                if not findings:
                    continue
                with st.expander(f"{labels[key]} — {len(findings)} finding(s)"):
                    for f in findings:
                        st.markdown(f"**IP:** `{f.ip}`")
                        st.markdown(f"&nbsp;&nbsp;&nbsp;{f.detail}")
                        st.divider()

    conn.close()

finally:
    os.unlink(tmp_log.name)
    if db_path and os.path.exists(db_path):
        os.unlink(db_path)
