#!/usr/bin/env python3
"""
streamlit_app.py
----------------
Phase 5: Visual dashboard for the heuristic_analyzer.py / merge_reports.py
output.

Usage:
    streamlit run streamlit_app.py

Then upload (or point at) final_report.json produced by merge_reports.py.

Requirements:
    pip install streamlit pandas plotly
"""

import json

import pandas as pd
import plotly.express as px
import streamlit as st

# Reuse the evaluation logic from evaluate.py (same folder).
try:
    from evaluate import flagged_pids_by_signal, metrics as eval_metrics
    _HAS_EVAL = True
except Exception:
    _HAS_EVAL = False

st.set_page_config(page_title="Memory Forensics Dashboard", layout="wide")

st.title("Memory Forensics Anomaly Dashboard")
st.caption("Volatility3-driven process, memory-region, thread & network anomaly triage")

# ---------------------------------------------------------------------------
# Load report
# ---------------------------------------------------------------------------

source = st.radio("Report source", ["Upload JSON", "Local file path"], horizontal=True)

report = None
if source == "Upload JSON":
    uploaded = st.file_uploader("Upload final_report.json", type="json")
    if uploaded:
        report = json.load(uploaded)
else:
    path = st.text_input("Path to report file", value="final_report.json")
    if path:
        try:
            with open(path) as f:
                report = json.load(f)
        except FileNotFoundError:
            st.warning(f"No file found at {path}")

if report is None:
    st.info("Load a report produced by `heuristic_analyzer.py` / `merge_reports.py` to continue.")
    st.stop()

# ---------------------------------------------------------------------------
# Summary row
# ---------------------------------------------------------------------------

summary = report.get("summary", {})
c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
c1.metric("Processes (pslist)", summary.get("total_processes_pslist", 0))
c2.metric("Processes (psscan)", summary.get("total_processes_psscan", 0))
c3.metric("Hidden / unlinked procs", summary.get("hidden_process_count", 0))
c4.metric("malfind RWX hits", summary.get("malfind_hit_count", 0))
c5.metric("Hashing threads", summary.get("hashing_thread_count", 0))
c6.metric("Network hits", summary.get("network_hit_count", 0))
c7.metric("Cross-category matches", summary.get("cross_category_match_count", 0))

st.divider()

# ---------------------------------------------------------------------------
# Process findings
# ---------------------------------------------------------------------------

st.subheader("Process Anomalies (pslist vs. psscan cross-reference)")

proc_findings = report.get("process_findings", [])
if proc_findings:
    df_proc = pd.DataFrame(proc_findings)
    df_proc["flags_str"] = df_proc["flags"].apply(lambda fl: ", ".join(fl))

    fig_proc = px.bar(
        df_proc.sort_values("score"),
        x="score", y="name", color="score",
        orientation="h",
        color_continuous_scale="Reds",
        hover_data=["pid", "ppid", "flags_str"],
        labels={"score": "Risk Score", "name": "Process"},
        title="Process risk score (higher = more suspicious)",
    )
    st.plotly_chart(fig_proc, use_container_width=True)

    st.dataframe(
        df_proc[["pid", "name", "ppid", "score", "flags_str"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("No process-level anomalies flagged.")

st.divider()

# ---------------------------------------------------------------------------
# Malfind findings (heatmap-style)
# ---------------------------------------------------------------------------

st.subheader("Flagged Memory Regions (windows.malfind)")

malfind_findings = report.get("malfind_findings", [])
if malfind_findings:
    df_mal = pd.DataFrame(malfind_findings)

    fig_heat = px.density_heatmap(
        df_mal, x="process", y="score",
        nbinsy=10,
        color_continuous_scale="Inferno",
        title="Malfind hit concentration by process / severity",
    )
    st.plotly_chart(fig_heat, use_container_width=True)

    st.dataframe(df_mal, use_container_width=True, hide_index=True)
else:
    st.success("No malfind hits in this image.")

st.divider()

# ---------------------------------------------------------------------------
# Hashing threads  (Option 2: thread-level CPU <-> unbacked-memory binding)
# ---------------------------------------------------------------------------

st.subheader("Hashing Threads (thread-level CPU ↔ unbacked-memory binding)")
st.caption("A thread flagged only when it BOTH executes from unbacked memory "
           "AND consumes abnormal CPU — isolating the specific hashing thread.")

hash_findings = report.get("hashing_thread_findings", [])
if hash_findings:
    df_thr = pd.DataFrame(hash_findings)
    if "reasons" in df_thr.columns:
        df_thr["reasons_str"] = df_thr["reasons"].apply(
            lambda r: ", ".join(r) if isinstance(r, list) else str(r))
    else:
        df_thr["reasons_str"] = ""

    # Scatter: unbacked (x) vs CPU cycles (y); HASHING_THREAD sits top-right.
    if {"cycle_time", "verdict"}.issubset(df_thr.columns):
        fig_thr = px.scatter(
            df_thr, x="verdict", y="cycle_time",
            size="score", color="verdict",
            hover_data=["pid", "tid", "process", "start_address", "reasons_str"],
            labels={"cycle_time": "Accumulated CPU cycles", "verdict": "Thread verdict"},
            title="Thread verdicts — HASHING_THREAD = unbacked + high CPU",
        )
        st.plotly_chart(fig_thr, use_container_width=True)

    cols = [c for c in ["pid", "tid", "process", "verdict", "unbacked",
                        "high_cpu", "cycle_time", "score", "reasons_str"]
            if c in df_thr.columns]
    st.dataframe(df_thr[cols], use_container_width=True, hide_index=True)
else:
    st.info("No hashing-thread findings loaded (run thread_binding.py on a dump, "
            "or thread_synth.py for the demo, then merge with --threads).")

st.divider()

# ---------------------------------------------------------------------------
# Network findings (netscan + flow correlation -- cryptojacking heuristic)
# ---------------------------------------------------------------------------

st.subheader("Network Anomalies (netscan + flow correlation)")

net_findings = report.get("network_findings", [])
if net_findings:
    df_net = pd.DataFrame(net_findings)
    df_net["flags_str"] = df_net["flags"].apply(lambda fl: ", ".join(fl))

    if "duration_seconds" in df_net.columns and "packets_per_minute" in df_net.columns:
        fig_scatter = px.scatter(
            df_net, x="duration_seconds", y="packets_per_minute",
            size="score", color="score", color_continuous_scale="Oranges",
            hover_data=["pid", "process", "foreign_ip", "foreign_port", "flags_str"],
            labels={"duration_seconds": "Flow duration (s)",
                    "packets_per_minute": "Packets/minute"},
            title="Mining-like flows cluster at long duration + steady low-frequency "
                  "(top area, right side)",
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    st.dataframe(
        df_net[["pid", "process", "foreign_ip", "foreign_port", "score", "flags_str"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No network findings loaded (run network_correlator.py + merge_reports.py "
            "to populate this section).")

st.divider()

# ---------------------------------------------------------------------------
# Combined top priority alerts across ALL categories
# ---------------------------------------------------------------------------

st.subheader("Top Priority Alerts (combined across all categories)")

combined_rows = []
for row in proc_findings:
    combined_rows.append({
        "category": "process", "pid": row["pid"], "process": row.get("name"),
        "score": row["score"], "detail": ", ".join(row.get("flags", [])),
    })
for row in malfind_findings:
    combined_rows.append({
        "category": "malfind", "pid": row["pid"], "process": row.get("process"),
        "score": row["score"],
        "detail": f"Protection: {row.get('protection')}, Start VPN: {row.get('start_vpn')}",
    })
for row in hash_findings:
    combined_rows.append({
        "category": "thread", "pid": row["pid"], "process": row.get("process"),
        "score": row.get("score", 0),
        "detail": f"{row.get('verdict')} (TID {row.get('tid')}): "
                  + ", ".join(row.get("reasons", [])),
    })
for row in net_findings:
    combined_rows.append({
        "category": "network", "pid": row["pid"], "process": row.get("process"),
        "score": row["score"], "detail": ", ".join(row.get("flags", [])),
    })

if combined_rows:
    df_combined = pd.DataFrame(combined_rows).sort_values("score", ascending=False).head(10)
    for _, row in df_combined.iterrows():
        with st.expander(f"[{row['category']}] PID {row['pid']} · {row['process']} · "
                          f"score {row['score']}"):
            st.write(row["detail"])
else:
    st.success("No anomalies flagged in any category.")

st.divider()

# ---------------------------------------------------------------------------
# Detection Accuracy (vs. ground-truth labels)   [from evaluate.py]
# ---------------------------------------------------------------------------

st.subheader("Detection Accuracy (vs. ground-truth labels)")
st.caption("Measures precision / recall / accuracy / false-positive rate per "
           "signal, and compares single-signal vs multi-signal. On SYNTHETIC "
           "data these numbers are illustrative only — real results need a "
           "real labeled dump.")

if not _HAS_EVAL:
    st.warning("evaluate.py not found next to this app — put it in the same folder "
               "to enable the accuracy section.")
else:
    gt_src = st.radio("Ground-truth source", ["Local file path", "Upload JSON"],
                      horizontal=True, key="gt_src")
    ground = None
    if gt_src == "Upload JSON":
        up = st.file_uploader("Upload ground_truth.json", type="json", key="gt_up")
        if up:
            ground = json.load(up)
    else:
        gp = st.text_input("Path to ground_truth.json", value="ground_truth.json")
        if gp:
            try:
                with open(gp) as f:
                    ground = json.load(f)
            except FileNotFoundError:
                st.info("No ground_truth.json found yet at that path.")

    if ground:
        malicious = ground.get("malicious_pids", [])
        benign = ground.get("benign_pids", [])
        st.write(f"Ground truth: **{len(malicious)}** malicious, "
                 f"**{len(benign)}** benign PIDs.")

        sigs = flagged_pids_by_signal(report)
        rows = []
        for name, flagged in sigs.items():
            m = eval_metrics(flagged, malicious, benign)
            rows.append({
                "signal": name,
                "TP": m["TP"], "FP": m["FP"], "FN": m["FN"], "TN": m["TN"],
                "precision": m["precision"], "recall": m["recall"],
                "accuracy": m["accuracy"], "FPR": m["fpr"],
            })
        df_eval = pd.DataFrame(rows)

        st.dataframe(
            df_eval.style.format({"precision": "{:.2f}", "recall": "{:.2f}",
                                  "accuracy": "{:.2f}", "FPR": "{:.2f}"},
                                 na_rep="n/a"),
            use_container_width=True, hide_index=True,
        )

        # Grouped bar: precision / recall / FPR per signal (the comparison story)
        plot_df = df_eval.melt(
            id_vars="signal", value_vars=["precision", "recall", "FPR"],
            var_name="metric", value_name="value").dropna(subset=["value"])
        if not plot_df.empty:
            fig_eval = px.bar(
                plot_df, x="signal", y="value", color="metric",
                barmode="group", range_y=[0, 1],
                title="Per-signal precision / recall / false-positive rate "
                      "(compare single signals vs MULTI-SIGNAL)",
            )
            fig_eval.update_xaxes(tickangle=-20)
            st.plotly_chart(fig_eval, use_container_width=True)

        st.caption("Lower FPR with maintained precision on the MULTI-SIGNAL / "
                   "thread-binding rows vs malfind-alone is the measured result.")
    else:
        st.info("Provide ground_truth.json (malicious_pids + benign_pids) to "
                "compute accuracy.")