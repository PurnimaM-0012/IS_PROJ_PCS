"""
live_view.py
------------
"Live network capture" page for streamlit_app.py.

Three ways to get live data in:
  1. Upload live_capture.json produced by `python live_capture.py ...`
     (recommended -- includes PID attribution and works for remote users).
  2. Upload a raw .pcap/.pcapng -- flows + domains only, no PIDs; needs
     tshark on the machine running Streamlit.
  3. "Capture now" button -- runs live_capture.py via subprocess. Only
     meaningful when Streamlit runs on the SAME machine with capture rights;
     it captures the server's traffic, not the browser user's.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

import pandas as pd
import plotly.express as px
import streamlit as st

from live_capture import analyze_capture, find_tshark, list_interfaces, parse_pcap
from network_correlator import DURATION_THRESHOLD_SECONDS

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_KEY = "live_capture_data"


def _load_json_upload():
    up = st.file_uploader("Upload live_capture.json", type="json", key="live_json")
    if not up:
        return
    file_id = f"{up.name}:{up.size}"
    if st.session_state.get("live_upload_id") == file_id:
        return  # already loaded (or cleared) this upload
    data = json.load(up)
    if "flows" not in data:
        st.error("This doesn't look like live_capture.py output (no `flows` key).")
        return
    st.session_state["live_upload_id"] = file_id
    st.session_state[STATE_KEY] = data


def _load_pcap_upload(tshark):
    if not tshark:
        st.error("tshark isn't installed on the machine running this dashboard, so "
                 "raw pcaps can't be parsed here. Upload live_capture.json instead.")
        return
    up = st.file_uploader("Upload .pcap / .pcapng", type=["pcap", "pcapng", "cap"],
                          key="live_pcap")
    if not up:
        return
    file_id = f"{up.name}:{up.size}"
    if st.session_state.get("live_pcap_id") == file_id:
        return  # already parsed this upload
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "upload.pcap")
        with open(path, "wb") as fh:
            fh.write(up.getbuffer())
        with st.spinner("Parsing pcap with tshark..."):
            flows, domains, packets = parse_pcap(tshark, path)
    st.session_state["live_pcap_id"] = file_id
    st.session_state[STATE_KEY] = {
        "capture_meta": {"source": f"pcap upload: {up.name}", "packet_count": packets,
                         "flow_count": len(flows), "connection_count": 0},
        "connections": [], "flows": flows, "domains": domains,
    }


def _capture_now(tshark):
    st.warning("**Local demo only.** This captures traffic on the machine running "
               "Streamlit, not on the viewer's computer, and needs packet-capture "
               "rights (Npcap, or run as Administrator/root).")
    if not tshark:
        st.error("tshark not found on this machine.")
        return
    try:
        ifaces = list_interfaces(tshark)
    except Exception as exc:
        st.error(f"Couldn't list interfaces: {exc}")
        return
    if not ifaces:
        st.error("tshark reported no capture interfaces (check Npcap / permissions).")
        return

    labels = [label for _, label in ifaces]
    default = next((i for i, l in enumerate(labels) if l.lower() in ("wi-fi", "ethernet")), 0)
    c1, c2 = st.columns([2, 1])
    label = c1.selectbox("Interface", labels, index=default)
    duration = c2.number_input("Duration (s)", min_value=10, max_value=1800,
                               value=360, step=30)
    if duration < DURATION_THRESHOLD_SECONDS:
        st.caption(f"⚠ Under {DURATION_THRESHOLD_SECONDS}s the long-lived-connection "
                   "heuristic can't fire.")

    if not st.button("Start capture", type="primary"):
        return

    device = ifaces[labels.index(label)][0]
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "live_capture.json")
        prog_file = os.path.join(tmp, "progress")
        cmd = [sys.executable, os.path.join(HERE, "live_capture.py"),
               "-i", device, "-d", str(int(duration)), "--out", out,
               "--tshark", tshark, "--progress-file", prog_file]
        proc = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        bar = st.progress(0.0, text="Starting capture...")
        while proc.poll() is None:
            try:
                with open(prog_file) as fh:
                    elapsed, total = map(float, fh.read().split())
                bar.progress(min(elapsed / total, 1.0),
                             text=f"Capturing on {label}: {elapsed:.0f}/{total:.0f}s")
            except (OSError, ValueError):
                pass
            time.sleep(1)
        bar.progress(1.0, text="Capture finished, analysing...")
        err = proc.stderr.read()
        if proc.returncode != 0 or not os.path.exists(out):
            st.error(f"Capture failed:\n\n```\n{err.strip()[-2000:]}\n```")
            return
        with open(out) as fh:
            st.session_state[STATE_KEY] = json.load(fh)


def _render_results(capture, min_score):
    meta = capture.get("capture_meta", {})
    findings = analyze_capture(capture)
    shown = [f for f in findings if f["score"] >= min_score]

    st.caption(" · ".join(f"{k}: {meta[k]}" for k in
                          ("source", "host", "interface", "started_utc") if meta.get(k)))
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Packets", meta.get("packet_count", 0))
    c2.metric("Flows", len(capture.get("flows", [])))
    c3.metric("PID-attributed conns", len(capture.get("connections", [])))
    c4.metric(f"Findings ≥ {min_score}", len(shown))
    c5.metric("Max score", max((f["score"] for f in findings), default=0))

    req = meta.get("requested_duration_seconds")
    if req and req < DURATION_THRESHOLD_SECONDS:
        st.info(f"This capture lasted {req}s, under the {DURATION_THRESHOLD_SECONDS}s "
                "long-lived-connection threshold, so that signal couldn't fire.")
    if not capture.get("connections"):
        st.info("No PID attribution in this data (raw pcap): findings show "
                "`(unattributed)`. Use live_capture.py to get process names.")

    st.download_button(
        "Download network_findings.json (for merge_reports.py)",
        json.dumps({"network_findings": findings}, indent=2),
        file_name="network_findings.json", mime="application/json")
    if meta.get("source") == "live_capture":
        st.download_button("Download raw live_capture.json",
                           json.dumps(capture, indent=2),
                           file_name="live_capture.json", mime="application/json")

    st.subheader("Mining-like connections")
    if shown:
        df = pd.DataFrame(shown)
        df["flags_str"] = df["flags"].apply(", ".join)
        df["pid"] = df["pid"].astype("Int64")
        if {"duration_seconds", "packets_per_minute"}.issubset(df.columns):
            plot_df = df.dropna(subset=["duration_seconds", "packets_per_minute"])
            if not plot_df.empty:
                fig = px.scatter(
                    plot_df, x="duration_seconds", y="packets_per_minute",
                    size="score", color="score", color_continuous_scale="Oranges",
                    hover_data=["pid", "process", "foreign_ip", "foreign_port",
                                "foreign_domain", "flags_str"],
                    labels={"duration_seconds": "Flow duration (s)",
                            "packets_per_minute": "Packets/minute"},
                    title="Live flows — mining-like traffic is long-lived with a "
                          "steady low packet rate")
                st.plotly_chart(fig, width="stretch")
        cols = [c for c in ["pid", "process", "foreign_ip", "foreign_port",
                            "foreign_domain", "score", "duration_seconds",
                            "avg_packet_size", "packets_per_minute", "flags_str"]
                if c in df.columns]
        st.dataframe(df[cols], width="stretch", hide_index=True)
    else:
        st.success(f"No connections scored ≥ {min_score}.")

    with st.expander(f"All captured flows ({len(capture.get('flows', []))})"):
        st.dataframe(pd.DataFrame(capture.get("flows", [])),
                     width="stretch", hide_index=True)
    if capture.get("connections"):
        with st.expander(f"Process ↔ connection map ({len(capture['connections'])})"):
            st.dataframe(pd.DataFrame(capture["connections"]).drop(
                columns=["first_seen", "last_seen"], errors="ignore"),
                width="stretch", hide_index=True)


def render():
    st.title("Live Network Capture")
    st.caption("Real traffic scored with the cryptojacking network heuristic "
               "(mining ports/domains, long-lived, small uniform packets, "
               "steady heartbeat).")

    with st.expander("How to capture (recommended workflow)", expanded=STATE_KEY not in st.session_state):
        st.markdown(
            "Run on the machine you want to inspect, then upload the JSON here:\n"
            "```bash\n"
            "python live_capture.py --list-interfaces\n"
            "python live_capture.py --interface \"Wi-Fi\" --duration 360 --out live_capture.json\n"
            "```\n"
            "Needs Wireshark/tshark (+ Npcap on Windows) and `pip install psutil`.")

    tshark = find_tshark()
    mode = st.radio("Data source",
                    ["Upload capture JSON", "Upload pcap", "Capture now (local)"],
                    horizontal=True)
    if mode == "Upload capture JSON":
        _load_json_upload()
    elif mode == "Upload pcap":
        _load_pcap_upload(tshark)
    else:
        _capture_now(tshark)

    capture = st.session_state.get(STATE_KEY)
    if not capture:
        st.info("Load or capture some traffic to see results.")
        return

    st.divider()
    min_score = st.slider("Minimum score to show", 0, 100, 40, step=10,
                          help="Weak signals alone (small packets, steady rate) are "
                               "common in normal HTTPS keep-alives and score 10–30.")
    _render_results(capture, min_score)
    if st.button("Clear loaded capture"):
        # Keep the *_id keys so a file still sitting in an uploader isn't
        # immediately reloaded; uploading a different file loads normally.
        st.session_state.pop(STATE_KEY, None)
        st.rerun()
