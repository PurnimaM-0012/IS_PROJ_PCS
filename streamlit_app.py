#!/usr/bin/env python3
"""
streamlit_app.py
----------------
Visual dashboard for real-machine cryptojacking triage.

Usage:
    streamlit run streamlit_app.py

Views (sidebar):
  * Forensics report      -- the report from kernel_dump_analyzer.py
                             (default: C:\\memdumps\\kernel_report.json)
  * Live network capture  -- live_capture.py output / pcap / local capture
  * Kernel memory dump    -- analyse a Task Manager live kernel dump

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

view = st.sidebar.radio("View", ["Forensics report", "Live network capture",
                                 "Kernel memory dump"], key="view")
if view == "Live network capture":
    from live_view import render as render_live
    render_live()
    st.stop()
if view == "Kernel memory dump":
    from memory_view import render as render_memory
    render_memory()
    st.stop()

st.title("Memory Forensics Anomaly Dashboard")
st.caption("Volatility3-driven process, memory-region, thread & network anomaly triage")

# ---------------------------------------------------------------------------
# Load report
# ---------------------------------------------------------------------------

DEFAULT_REPORT = r"C:\memdumps\kernel_report.json"

source = st.radio("Report source", ["Local file path", "Upload JSON"], horizontal=True,
                  key="report_source")

report = None
if source == "Upload JSON":
    uploaded = st.file_uploader("Upload a report JSON", type="json")
    if uploaded:
        report = json.load(uploaded)
else:
    path = st.text_input("Path to report file",
                         value=st.session_state.get("report_path_default", DEFAULT_REPORT))
    if path:
        try:
            with open(path) as f:
                report = json.load(f)
        except FileNotFoundError:
            st.warning(f"No report at {path} yet.")

if report is None:
    st.info("No report loaded. Create one on the **Kernel memory dump** page (sidebar): "
            "take a Task Manager live kernel dump, then click *Analyse dump*.")
    st.stop()

for note in report.get("analysis_notes", []):
    st.caption(f"ℹ {note}")

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

    # One bar per process: how many flagged regions it has, coloured by the
    # highest score among them (top 20 processes by count).
    agg = {"regions": ("score", "size"), "max_score": ("score", "max")}
    if "size_kb" in df_mal.columns:
        agg["total_kb"] = ("size_kb", "sum")
    df_bar = (df_mal.groupby("process", as_index=False).agg(**agg)
              .sort_values("regions", ascending=False).head(20)
              .sort_values("regions"))
    fig_bar = px.bar(
        df_bar, x="regions", y="process", orientation="h",
        color="max_score", color_continuous_scale="Reds", range_color=[0, 100],
        hover_data=[c for c in ("max_score", "total_kb") if c in df_bar.columns],
        labels={"regions": "Flagged RWX regions", "process": "Process",
                "max_score": "Highest score", "total_kb": "Total size (KB)"},
        title="Flagged memory regions per process (top 20)",
    )
    fig_bar.update_layout(height=max(300, 28 * len(df_bar) + 120))
    st.plotly_chart(fig_bar, use_container_width=True)

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
    st.success("No suspicious threads flagged in this dump.")

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
st.caption("Precision / recall / false-positive rate per signal, measured against "
           "processes you label in this dump. Memory forensics and network analysis "
           "are evaluated separately.")

if not _HAS_EVAL:
    st.warning("evaluate.py not found next to this app — put it in the same folder "
               "to enable the accuracy section.")
else:
    proc_list = report.get("process_list", [])
    ground = None
    if not proc_list:
        st.info("This report has no process list, so it can't be labelled. Re-analyse "
                "the dump on the Kernel memory dump page to enable accuracy.")
    else:
        st.caption("Enter the PID(s) you KNOW are malicious (e.g. the PID rwx_demo.py "
                   "printed). Every other process running in this dump counts as benign.")
        names = {r["pid"]: r["name"] for r in proc_list}
        raw = st.text_input("Malicious PIDs (comma-separated)", key="gt_mal_pids")
        try:
            mal = {int(x) for x in raw.replace(" ", "").split(",") if x}
        except ValueError:
            st.error("PIDs must be numbers, e.g. 12345, 6789")
            mal = set()
        missing = sorted(mal - names.keys())
        if missing:
            st.warning(f"Not running in this dump: {missing}. Was the process still "
                       "running when the dump was taken?")
        if mal & names.keys():
            st.write("Malicious: " + ", ".join(f"{p} ({names[p]})" for p in sorted(mal & names.keys())))
            ground = {"malicious_pids": sorted(mal & names.keys()),
                      "benign_pids": sorted(names.keys() - mal)}

    if ground:
        malicious = ground.get("malicious_pids", [])
        benign = ground.get("benign_pids", [])
        st.write(f"Ground truth: **{len(malicious)}** malicious, "
                 f"**{len(benign)}** benign PIDs.")

        sigs = flagged_pids_by_signal(report)
        MEM = ["process (pslist/psscan)", "malfind (RWX region)",
               "thread-binding (HASHING_THREAD)"]
        NET = "network (mining traffic)"
        mem_counts = {}
        for name in MEM:
            for pid in sigs[name]:
                mem_counts[pid] = mem_counts.get(pid, 0) + 1
        mem_any = set(mem_counts)
        mem_multi = {p for p, c in mem_counts.items() if c >= 2}

        # Network analysis can only judge processes that used the network.
        net_pop = report.get("network_observed_pids")
        if net_pop is not None:
            net_mal = [p for p in malicious if p in set(net_pop)]
            net_ben = [p for p in benign if p in set(net_pop)]
        else:
            net_mal, net_ben = malicious, benign
        has_network = bool(report.get("network_findings")) or net_pop is not None

        def _why_undefined(metric, m):
            if metric == "precision":
                return "no alarms raised"
            if metric == "recall":
                return "no malicious process in this population"
            return "no benign process in this population"

        def _signal_card(title, m, what):
            with st.container(border=True):
                st.markdown(f"**{title}**")
                st.caption(what)
                c = st.columns(4)
                c[0].metric("Alarms raised", m["TP"] + m["FP"],
                            help="Processes this signal flagged (TP + FP)")
                for col, key, label, hint in (
                        (c[1], "precision", "Precision", "Of its alarms, share that were real"),
                        (c[2], "recall", "Recall", "Of the malicious processes, share it caught"),
                        (c[3], "fpr", "False-positive rate", "Share of benign processes falsely flagged")):
                    v = m[key]
                    col.metric(label, "—" if v is None else f"{v:.2f}",
                               help=hint + ("" if v is not None
                                            else f". Undefined: {_why_undefined(key, m)}."))
                st.caption(f"TP {m['TP']} · FP {m['FP']} · FN {m['FN']} · TN {m['TN']}")

        def _technique_chart(rows, title):
            plot = []
            for name, m in rows:
                for key, label in (("precision", "Precision"), ("recall", "Recall"),
                                   ("fpr", "False-positive rate")):
                    v = m[key]
                    plot.append({"signal": name, "metric": label,
                                 "value": 0 if v is None else v,
                                 "label": "n/a" if v is None else f"{v:.2f}"})
            fig = px.bar(pd.DataFrame(plot), x="signal", y="value", color="metric",
                         barmode="group", range_y=[0, 1.1], text="label", title=title,
                         labels={"value": "", "signal": ""})
            fig.update_traces(textposition="outside")
            st.plotly_chart(fig, use_container_width=True)

        all_rows = []
        tab_mem, tab_net, tab_comb = st.tabs(
            ["🧠 Memory forensics", "🌐 Network analysis", "🔗 Combined"])

        with tab_mem:
            st.caption(f"Evaluated on every labelled process in the dump "
                       f"({len(malicious)} malicious, {len(benign)} benign).")
            mem_rows = [(n, eval_metrics(sigs[n], malicious, benign)) for n in MEM]
            mem_rows.append(("≥2 memory signals agree",
                             eval_metrics(mem_multi, malicious, benign)))
            descr = {
                MEM[0]: "Process hidden from the OS list but found by scanning",
                MEM[1]: "Private executable + writable memory region",
                MEM[2]: "A thread in unbacked memory that also burns abnormal CPU",
                "≥2 memory signals agree": "Flagged by two or more memory signals",
            }
            cols = st.columns(2)
            for i, (name, m) in enumerate(mem_rows):
                with cols[i % 2]:
                    _signal_card(name, m, descr[name])
            _technique_chart(mem_rows, "Memory forensics signals")
            all_rows += [("memory", n, m) for n, m in mem_rows]

        with tab_net:
            if not has_network:
                st.info("No network data in this report. Supply a live capture "
                        "(taken around the same time) when analysing the dump.")
            else:
                if net_pop is not None:
                    st.caption(f"Evaluated only on the {len(net_mal) + len(net_ben)} labelled "
                               "processes that made network connections during the capture "
                               "— the network signal can't see the others.")
                else:
                    st.caption("This report doesn't list which processes used the network, "
                               "so every labelled process is counted.")
                m = eval_metrics(sigs[NET], net_mal, net_ben)
                if not net_mal:
                    st.warning("The malicious process made no network connections during "
                               "the capture, so recall can't be measured here — network "
                               "analysis had nothing to detect.")
                _signal_card(NET, m, "Mining-like connection (ports, pool domains, "
                                     "long-lived steady small packets), score ≥ 80")
                all_rows.append(("network", NET, m))

        with tab_comb:
            st.caption("Not a comparison between the techniques: this asks whether "
                       "independent evidence from BOTH agrees on the same process.")
            if not has_network:
                st.info("Needs network data to combine with the memory findings.")
            else:
                both = mem_any & sigs[NET]
                m = eval_metrics(both, malicious, benign)
                _signal_card("Memory AND network agree", m,
                             "Flagged by at least one memory signal and by network analysis")
                all_rows.append(("combined", "Memory AND network agree", m))

        with st.expander("All counts (incl. accuracy)"):
            st.caption("Accuracy is shown for completeness but is misleading here: with "
                       f"{len(malicious)} malicious vs {len(benign)} benign processes, a "
                       "detector that flags nothing still scores ~1.00.")
            st.dataframe(pd.DataFrame([{
                "technique": t, "signal": n, "TP": m["TP"], "FP": m["FP"], "FN": m["FN"],
                "TN": m["TN"], "precision": m["precision"], "recall": m["recall"],
                "FPR": m["fpr"], "accuracy": m["accuracy"]} for t, n, m in all_rows]).style
                .format({k: "{:.2f}" for k in ("precision", "recall", "FPR", "accuracy")},
                        na_rep="n/a"),
                use_container_width=True, hide_index=True)
    elif proc_list:
        st.info("Enter the malicious PID(s) above to compute accuracy.")