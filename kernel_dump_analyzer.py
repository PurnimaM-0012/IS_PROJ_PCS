#!/usr/bin/env python3
"""
kernel_dump_analyzer.py
------------------------
Analyses a Windows KERNEL-ONLY live memory dump (Task Manager -> Details ->
right-click "System" -> Create live kernel memory dump file -> Full live
kernel memory dump, with "Capture user pages" OFF) and writes a report in
the same format as merge_reports.py, so the dashboard shows it directly.

Why a separate analyzer instead of heuristic_analyzer.py:
  * Task Manager writes DumpType 0x6 (kernel bitmap), which stock
    Volatility3 can't open -> vol_plugins/kernel_bitmap_dump.py adds it.
  * Kernel-only dumps contain no user-mode page CONTENTS, and
    windows.malfind silently drops every region it can't read
    (is_vad_empty). The protection flags it filters on live in the
    kernel's VAD tree, so we apply the same filter without the content
    check ("vad_scan"). The +20 "MZ header" bonus can't apply.
  * Every `vol` CLI call repeats ~4 min of automagic; this opens the dump
    ONCE and runs every check on the same context.
  * windows.netscan has no structure layout for Windows 11 24H2
    (build >= 26100) as of Volatility 2.28.2 and returns 0 rows, so the
    PID <-> connection map comes from a live_capture.py run taken at the
    same time (pass --live-capture).

Usage:
    python kernel_dump_analyzer.py --dump C:\\memdumps\\livedump.dmp \
        --out C:\\memdumps\\kernel_report.json \
        [--live-capture live_capture.json] [--delete-dump]
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

from heuristic_analyzer import score_malfind_hit, score_process
from thread_binding import ThreadSample, bind_threads, to_report_section

HERE = Path(__file__).resolve().parent
VOL_PLUGIN_DIR = HERE / "vol_plugins"
# x64 user space ends at 0x00007FFFFFFFFFFF. Volatility may return kernel
# start addresses without sign extension (0xf801...), so compare the low 48 bits.
KERNEL_SPACE = 0x800000000000
NETWORK_MIN_SCORE = 40   # same default as the live view; weaker hits are HTTPS keep-alive noise


class Progress:
    """Writes {"stage", "pct", ...} to a JSON file the dashboard polls."""

    def __init__(self, path=None):
        self.path = path
        self.started = time.time()

    def __call__(self, stage, pct, **extra):
        msg = {"stage": stage, "pct": round(pct, 1),
               "elapsed_s": round(time.time() - self.started), **extra}
        print(f"[{msg['elapsed_s']:>4}s] {pct:5.1f}%  {stage}", file=sys.stderr, flush=True)
        if self.path:
            tmp = f"{self.path}.tmp"
            with open(tmp, "w") as fh:
                json.dump(msg, fh)
            os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Volatility setup (once per run)
# ---------------------------------------------------------------------------

def open_dump(dump_path, progress):
    """Build a Volatility context for the dump. Returns (ctx, kernel module)."""
    logging.getLogger("volatility3").setLevel(logging.ERROR)
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, interfaces, plugins

    # Same as `vol -p vol_plugins`: registers the DumpType 0x6 stacker.
    volatility3.plugins.__path__.append(str(VOL_PLUGIN_DIR))
    framework.import_files(volatility3.plugins, True)

    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = Path(dump_path).resolve().as_uri()
    plugin_cls = framework.list_plugins()["windows.pslist.PsList"]
    amagic = automagic.choose_automagic(automagic.available(ctx), plugin_cls)

    def cb(pct, desc):
        progress(f"Loading dump: {desc}", 5 + pct * 0.25)

    constructed = plugins.construct_plugin(
        ctx, amagic, plugin_cls,
        interfaces.configuration.path_join("plugins", "PsList"), cb, None)
    return ctx, ctx.modules[constructed.config["kernel"]]


def _name(proc):
    try:
        return proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                       errors="replace")
    except Exception:
        return "?"


def _has_exited(proc):
    try:
        return int(proc.ExitTime.QuadPart) != 0
    except Exception:
        return False


def _proc_row(proc):
    return {"PID": int(proc.UniqueProcessId),
            "PPID": int(proc.InheritedFromUniqueProcessId),
            "ImageFileName": _name(proc)}


# ---------------------------------------------------------------------------
# Per-process checks
# ---------------------------------------------------------------------------

def scan_process_memory(ctx, kernel, proc, protect_values):
    """One VAD walk per process. Returns (suspicious regions in malfind_findings
    shape, "backed" ranges for thread binding).

    A thread counts as unbacked only if it starts inside PRIVATE executable
    memory with no file behind it -- what VirtualAlloc'd / injected code looks
    like. A kernel-only dump often lacks the paged structures holding an
    image's file name, or a VAD entirely, so "not found in a known image" is
    *unknown*, not "injected". We therefore hand bind_threads() the
    complement of the private-executable ranges as its backed ranges."""
    from volatility3.plugins.windows import vadinfo

    pid, name = int(proc.UniqueProcessId), _name(proc)
    hits, private_exec = [], []
    try:
        vads = list(proc.get_vad_root().traverse())
    except Exception:
        return hits, [(0, KERNEL_SPACE)]

    for vad in vads:
        try:
            prot = vad.get_protection(protect_values, vadinfo.winnt_protections)
            if "EXECUTE" not in prot:
                continue
            start, end = int(vad.get_start()), int(vad.get_end())
            try:
                fname = vad.get_file_name()
                fname = fname if isinstance(fname, str) else ""
            except Exception:
                fname = ""
            is_private = vad.get_private_memory() == 1
            if is_private and not fname:
                private_exec.append((start, end + 1))

            # malfind's filter, minus the page-content check (no user pages).
            if "WRITE" not in prot:
                continue
            private = is_private and vad.get_tag() == "VadS"
            mapped_odd = vad.get_private_memory() == 0 and prot != "PAGE_EXECUTE_WRITECOPY"
            if not (private or mapped_odd):
                continue
            hit = {"PID": pid, "Process": name, "Start VPN": start, "Protection": prot}
            hits.append({
                "pid": pid, "process": name, "start_vpn": start, "end_vpn": end,
                "size_kb": (end - start + 1) // 1024, "protection": prot,
                "backing": fname or "private (unbacked)",
                "detector": "vad_scan (kernel-only; content not available)",
                "score": score_malfind_hit(hit),
            })
        except Exception:
            continue

    # complement of private-executable ranges within user space
    backed, cursor = [], 0
    for lo, hi in sorted(private_exec):
        if lo > cursor:
            backed.append((cursor, lo))
        cursor = max(cursor, hi)
    backed.append((cursor, KERNEL_SPACE))
    return hits, backed


def thread_samples(kernel, proc, image_ranges):
    from volatility3.framework import constants

    pid, name = int(proc.UniqueProcessId), _name(proc)
    out = []
    try:
        threads = proc.ThreadListHead.to_list(
            f"{kernel.symbol_table_name}{constants.BANG}_ETHREAD", "ThreadListEntry")
        for t in threads:
            try:
                tid = int(t.Cid.UniqueThread)
                start = int(t.Win32StartAddress)
            except Exception:
                continue
            # Kernel threads (System, Registry, MemCompression...) start in
            # kernel modules, which have no user VADs -- not "unbacked".
            if start == 0 or (start & 0xFFFFFFFFFFFF) >= KERNEL_SPACE:
                continue
            try:
                cycles = int(t.Tcb.CycleTime)
            except Exception:
                cycles = 0
            out.append(ThreadSample(pid=pid, tid=tid, process=name, start_address=start,
                                    cycle_time=cycles, image_exec_ranges=image_ranges))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(dump_path, progress=None, live_capture=None):
    progress = progress or Progress()
    from volatility3.plugins.windows import pslist, psscan, vadinfo

    progress("Opening dump (first run downloads Windows symbols)", 2)
    ctx, kernel = open_dump(dump_path, progress)

    progress("Listing processes (pslist)", 32)
    listed = list(pslist.PsList.list_processes(ctx, kernel.name))
    progress("Scanning for process structures (psscan)", 38)
    scanned = list(psscan.PsScan.scan_processes(ctx, kernel.name))

    pslist_pids = {int(p.UniqueProcessId) for p in listed}
    psscan_pids = {int(p.UniqueProcessId) for p in scanned}
    # psscan also finds processes that simply EXITED; their structures linger
    # in memory. Only a psscan-only process that is still running is "hidden".
    exited = [p for p in scanned if _has_exited(p)]
    running_scanned = [p for p in scanned if not _has_exited(p)]
    process_findings = [score_process(_proc_row(p), pslist_pids, psscan_pids)
                        for p in running_scanned]
    process_findings = [f for f in process_findings if f["score"] > 0]

    # Processes to inspect: everything still running, incl. hidden ones.
    seen, to_scan = set(), []
    for p in listed + running_scanned:
        pid = int(p.UniqueProcessId)
        if pid not in seen:
            seen.add(pid)
            to_scan.append(p)

    protect_values = vadinfo.VadInfo.protect_values(ctx, kernel.layer_name,
                                                    kernel.symbol_table_name)
    memory_hits, samples = [], []
    for i, proc in enumerate(to_scan, 1):
        if i % 10 == 0 or i == len(to_scan):
            progress(f"Scanning memory regions + threads ({i}/{len(to_scan)})",
                     45 + 45 * i / len(to_scan))
        hits, ranges = scan_process_memory(ctx, kernel, proc, protect_values)
        memory_hits.extend(hits)
        samples.extend(thread_samples(kernel, proc, ranges))

    progress("Binding threads (unbacked + high CPU)", 92)
    hashing = to_report_section(bind_threads(samples, log_scale=True))["hashing_thread_findings"]

    report = {
        "image": str(dump_path),
        "dump_type": "windows_live_kernel_dump (kernel pages only)",
        "analysis_notes": [
            "Memory-region findings come from VAD protection flags (vad_scan); "
            "page contents are not in a kernel-only dump, so the MZ-header check is skipped.",
            "JIT engines (browsers, Electron apps, .NET) legitimately allocate "
            "private RWX memory, so expect vad_scan hits there.",
            "windows.netscan has no layout for this Windows build; network data "
            "comes from a live capture when one is supplied.",
        ],
        "summary": {
            "total_processes_pslist": len(listed),
            "total_processes_psscan": len(scanned),
            "exited_process_count": len(exited),
            "hidden_process_count": sum(
                1 for f in process_findings if "hidden_from_pslist" in " ".join(f["flags"])),
            "malfind_hit_count": len(memory_hits),
            "threads_examined": len(samples),
        },
        "process_findings": sorted(process_findings, key=lambda f: -f["score"]),
        "malfind_findings": sorted(memory_hits, key=lambda f: -f["score"]),
        # every running process, so the dashboard can build ground truth for
        # THIS dump (known-malicious PIDs vs. everything else = benign)
        "process_list": sorted(({"pid": int(p.UniqueProcessId), "name": _name(p)}
                                for p in to_scan), key=lambda r: r["pid"]),
    }

    # Merge with network + threads via the existing merge_reports.merge().
    progress("Merging findings", 96)
    from merge_reports import merge
    network = {"network_findings": []}
    if live_capture:
        from live_capture import analyze_capture
        network = {"network_findings": [f for f in analyze_capture(live_capture)
                                        if f["score"] >= NETWORK_MIN_SCORE]}
        report["network_source"] = live_capture.get("capture_meta", {})
        # processes that actually used the network -- the population the
        # network signal can be evaluated on
        report["network_observed_pids"] = sorted(
            {c["PID"] for c in live_capture.get("connections", []) if c.get("PID")})
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for key, data in (("report", report), ("network", network),
                          ("threads", {"hashing_thread_findings": hashing})):
            paths[key] = os.path.join(tmp, f"{key}.json")
            with open(paths[key], "w") as fh:
                json.dump(data, fh)
        merged = merge(paths["report"], paths["network"], paths["threads"])
    progress("Done", 100)
    return merged


def main():
    ap = argparse.ArgumentParser(description="Analyse a Task Manager live kernel dump")
    ap.add_argument("--dump", required=True, help="path to livedump.dmp")
    ap.add_argument("--out", required=True, help="report JSON (keep it out of the repo)")
    ap.add_argument("--live-capture", help="live_capture.json taken around the same time")
    ap.add_argument("--delete-dump", action="store_true", help="delete the dump afterwards")
    ap.add_argument("--progress-file", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.delete_dump:
        # Volatility keeps the dump file open until the process exits, so the
        # analysis runs in a child process and we delete once it has finished.
        import subprocess
        child = [sys.executable, os.path.abspath(__file__)] + \
                [a for a in sys.argv[1:] if a != "--delete-dump"]
        rc = subprocess.call(child)
        if rc == 0:
            try:
                os.remove(args.dump)
                print(f"[+] Deleted {args.dump}")
            except OSError as exc:
                print(f"[!] Couldn't delete the dump ({exc}). In an Administrator "
                      f'PowerShell: Remove-Item "{args.dump}"')
        sys.exit(rc)

    progress = Progress(args.progress_file)
    try:
        with open(args.dump, "rb") as fh:
            fh.read(8)
    except PermissionError:
        progress("error", 0, error="permission_denied")
        sys.exit(f"[-] Can't read {args.dump}: Task Manager saves dumps as admin-only. "
                 "In an Administrator PowerShell run:\n"
                 f'    icacls "{args.dump}" /grant "$env:USERDOMAIN\\$env:USERNAME:(R,D)"')
    except FileNotFoundError:
        progress("error", 0, error="not_found")
        sys.exit(f"[-] Dump not found: {args.dump}")

    capture = None
    if args.live_capture:
        with open(args.live_capture) as fh:
            capture = json.load(fh)

    try:
        report = analyze(args.dump, progress, capture)
    except Exception as exc:
        progress("error", 0, error=f"{type(exc).__name__}: {exc}")
        raise
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Report written to {args.out}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
