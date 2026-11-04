"""
memory_view.py
--------------
"Kernel memory dump" page for streamlit_app.py.

Flow: create a live kernel dump with Task Manager (user pages OFF) ->
pick it here -> analysis runs in a BACKGROUND process (so a page refresh
doesn't kill it) -> report opens in the Forensics report view.

The dump is never uploaded: Streamlit runs on the same machine, so the
analyzer reads it from disk. Only the small JSON report is shown.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

HERE = Path(__file__).resolve().parent
DUMP_DIR = Path(r"C:\memdumps")
TASKMGR_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Windows/TaskManager/LiveKernelDumps"
JOB_FILE = DUMP_DIR / "kernel_job.json"   # lets a refreshed page re-attach to a running job


def _readable(path):
    try:
        with open(path, "rb") as fh:
            fh.read(8)
        return True
    except OSError:
        return False


def _find_dumps():
    found = []
    for d in (DUMP_DIR, TASKMGR_DIR):
        try:
            found += [p for p in d.glob("*.dmp")] + [p for p in d.glob("*.DMP")]
        except OSError:
            pass
    uniq = {str(p).lower(): p for p in found}
    return sorted(uniq.values(), key=lambda p: p.stat().st_mtime, reverse=True)


def _pid_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid) and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False


def _load_job():
    try:
        return json.loads(JOB_FILE.read_text())
    except (OSError, ValueError):
        return None


def _admin_fix_cmd(src):
    return (
        "New-Item -ItemType Directory -Force C:\\memdumps | Out-Null\n"
        f'Move-Item "{src}" C:\\memdumps\\{Path(src).name.lower()}\n'
        # R = read for analysis, D = lets the app delete it afterwards
        f'icacls C:\\memdumps\\{Path(src).name.lower()} /grant "$env:USERDOMAIN\\$env:USERNAME:(R,D)"'
    )


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def _step_create():
    with st.expander("1 · Create a kernel-only dump with Task Manager",
                     expanded=not _find_dumps()):
        st.markdown(
            "1. Close heavy apps first (browsers, IDEs): a live dump needs free RAM "
            "roughly the size of kernel memory, or Windows aborts it with "
            "*system memory pressure*.\n"
            "2. Task Manager → **Settings** (gear) → *Kernel dump settings*: make sure "
            "**Capture user pages** and **Capture hypervisor pages** are **off**. "
            "This is what keeps passwords, cookies and documents out of the dump.\n"
            "3. **Details** tab → right-click **System** → *Create live kernel memory "
            "dump file* → **Full live kernel memory dump**.\n"
            "4. Task Manager saves it as admin-only. Run the command shown in step 2 "
            "(Administrator PowerShell) to move it to `C:\\memdumps` and let this app "
            "read it.")
        st.caption("Tip: for network correlation, run a live network capture "
                   "(Live network capture page or `live_capture.py`) for ~6 minutes "
                   "just before taking the dump.")
        if st.button("Open Task Manager"):
            try:
                subprocess.Popen(["taskmgr.exe"])
            except OSError as exc:
                st.error(f"Couldn't start Task Manager: {exc}")


def _step_pick_dump():
    st.markdown("#### 2 · Choose the dump")
    dumps = _find_dumps()
    options = [str(p) for p in dumps] + ["Other path…"]
    labels = {}
    for p in dumps:
        st_ = p.stat()
        labels[str(p)] = (f"{p}  ·  {st_.st_size / 2**30:.2f} GB  ·  "
                          f"{datetime.fromtimestamp(st_.st_mtime):%d %b %H:%M}"
                          + ("" if _readable(p) else "  ·  🔒 admin-only"))
    choice = st.selectbox("Dump file", options, format_func=lambda o: labels.get(o, o))
    path = st.text_input("Path", value=r"C:\memdumps\livedump.dmp") if choice == "Other path…" else choice

    if not path:
        return None
    if not os.path.exists(path):
        st.warning("File not found.")
        return None
    if "onedrive" in path.lower():
        st.error("This dump is inside a OneDrive folder, so it is being uploaded to the "
                 "cloud. Move it to C:\\memdumps and delete it from OneDrive.")
    if not _readable(path):
        st.error("This file is admin-only (Task Manager's default). Run in an "
                 "**Administrator PowerShell**, then refresh:")
        st.code(_admin_fix_cmd(path), language="powershell")
        return None
    return path


def _step_network():
    st.markdown("#### 3 · Network data (optional)")
    st.caption("Volatility's netscan can't read connections on Windows 11 24H2+, so "
               "the process ↔ connection map comes from a live capture taken around "
               "the same time.")
    opts = ["None"]
    if st.session_state.get("live_capture_data"):
        opts.append("Capture loaded on the Live network capture page")
    opts.append("live_capture.json file")
    src = st.radio("Network source", opts, horizontal=True, key="mem_net_src")
    if src == "None":
        return None
    if src.startswith("Capture loaded"):
        return st.session_state["live_capture_data"]
    p = st.text_input("Path to live_capture.json", value=str(HERE / "live_capture.json"))
    try:
        with open(p) as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        st.warning(f"Couldn't read it: {exc}")
        return None


def _start_job(dump, capture, out, delete_dump):
    DUMP_DIR.mkdir(exist_ok=True)
    progress = DUMP_DIR / "kernel_progress.json"
    log = DUMP_DIR / "kernel_analysis.log"
    cmd = [sys.executable, str(HERE / "kernel_dump_analyzer.py"),
           "--dump", dump, "--out", out, "--progress-file", str(progress)]
    if capture:
        cap_path = DUMP_DIR / "kernel_job_capture.json"
        cap_path.write_text(json.dumps(capture))
        cmd += ["--live-capture", str(cap_path)]
    if delete_dump:
        cmd.append("--delete-dump")
    progress.unlink(missing_ok=True)
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    with open(log, "w") as log_fh:
        proc = subprocess.Popen(cmd, cwd=str(HERE), stdout=log_fh, stderr=log_fh,
                                creationflags=flags)
    JOB_FILE.write_text(json.dumps({
        "pid": proc.pid, "dump": dump, "out": out, "progress": str(progress),
        "log": str(log), "started": time.time()}))


def _open_report(path):
    st.session_state["report_path_default"] = path
    st.session_state["report_source"] = "Local file path"
    st.session_state["view"] = "Forensics report"


@st.fragment(run_every=3)
def _job_status():
    job = _load_job()
    if not job:
        return
    alive = _pid_alive(job["pid"])
    try:
        prog = json.loads(Path(job["progress"]).read_text())
    except (OSError, ValueError):
        prog = {"stage": "Starting…", "pct": 0}

    st.markdown("#### Analysis")
    if prog.get("stage") == "error":
        st.error(f"Analysis failed: {prog.get('error')}")
    elif alive:
        st.progress(min(prog.get("pct", 0) / 100, 1.0),
                    text=f"{prog.get('stage')} · {prog.get('elapsed_s', 0)}s elapsed")
        st.caption("Runs in the background: you can switch pages or refresh. "
                   "First run takes longer (Windows symbol download).")
        return
    elif prog.get("stage") == "Done" and os.path.exists(job["out"]):
        try:
            summary = json.loads(Path(job["out"]).read_text()).get("summary", {})
        except (OSError, ValueError):
            summary = {}
        st.success(f"Analysis finished in {prog.get('elapsed_s', '?')}s → `{job['out']}`")
        cols = st.columns(5)
        for col, (label, key) in zip(cols, [
                ("Processes", "total_processes_pslist"),
                ("Hidden procs", "hidden_process_count"),
                ("RWX regions", "malfind_hit_count"),
                ("Flagged threads", "hashing_thread_count"),
                ("Network hits", "network_hit_count")]):
            col.metric(label, summary.get(key, 0))
        # The callback sets the sidebar/radio state before the next run; the
        # explicit app-wide rerun is needed because a click inside a fragment
        # otherwise reruns only the fragment, leaving the page unchanged.
        if st.button("Open full report", type="primary", on_click=_open_report,
                     args=(job["out"],)):
            st.rerun(scope="app")
        if os.path.exists(job["dump"]):
            st.warning(f"The dump is still on disk. It contains kernel memory: delete "
                       "it when you're done (Administrator PowerShell):")
            st.code(f'Remove-Item "{job["dump"]}"', language="powershell")
    else:
        st.error("The analysis stopped unexpectedly.")

    try:
        log_tail = Path(job["log"]).read_text(errors="replace").splitlines()[-15:]
        with st.expander("Analyzer log"):
            st.code("\n".join(l for l in log_tail if "yara" not in l.lower()))
    except OSError:
        pass
    if st.button("Clear job"):
        JOB_FILE.unlink(missing_ok=True)
        st.rerun()


def render():
    st.title("Kernel Memory Dump")
    st.caption("Memory forensics on a Task Manager live kernel dump: hidden processes, "
               "executable+writable memory and hashing threads, with no user-mode "
               "page contents (no passwords, cookies or documents).")

    if os.name != "nt":
        st.error("Live kernel dumps are a Windows feature; run this dashboard on the "
                 "Windows machine being examined.")
        return

    job = _load_job()
    running = bool(job and _pid_alive(job["pid"]))

    _step_create()
    dump = _step_pick_dump()
    capture = _step_network()

    st.markdown("#### 4 · Analyse")
    out = st.text_input("Report path (keep it outside the project folder)",
                        value=str(DUMP_DIR / "kernel_report.json"))
    delete_dump = st.checkbox("Delete the dump after analysis", value=True)
    if st.button("Analyse dump", type="primary", disabled=running or not dump):
        if str(HERE).lower() in os.path.abspath(out).lower():
            st.error("Write the report outside the project folder: it holds this "
                     "machine's real process list and shouldn't end up in git.")
        else:
            _start_job(dump, capture, out, delete_dump)
            st.rerun()
    if running:
        st.caption("An analysis is already running.")

    _job_status()
