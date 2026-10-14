#!/usr/bin/env python3
"""
heuristic_analyzer.py
----------------------
Phase 3 + Phase 4: Runs Volatility3 against a memory image, parses the
output, and applies a simple heuristic scoring model to flag processes /
memory regions that look like code injection or hidden execution.

Usage:
    python heuristic_analyzer.py --image /path/to/memory.raw --out report.json

Requirements:
    pip install volatility3
    (Volatility3 must be able to find a matching Windows symbol table for
    the image's OS build — see the README for how to fetch/build these.)

This script shells out to the `vol` CLI (ships with volatility3) using its
JSON renderer (-r json), which keeps this script free of any dependency on
Volatility3's internal Python API versioning.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Volatility invocation helpers
# ---------------------------------------------------------------------------

def run_vol_plugin(image_path: str, plugin: str, extra_args=None) -> list:
    """
    Runs a single Volatility3 plugin against the image and returns the
    parsed JSON rows. Returns [] on failure (and prints the stderr for
    debugging) rather than raising, so one broken plugin doesn't kill
    the whole scan.
    """
    cmd = ["vol", "-q", "-r", "json", "-f", image_path, plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1800, check=False
        )
    except FileNotFoundError:
        print("ERROR: 'vol' command not found. Is volatility3 installed "
              "and on PATH? (pip install volatility3)", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"WARNING: {plugin} timed out after 30 minutes", file=sys.stderr)
        return []

    if proc.returncode != 0:
        print(f"WARNING: {plugin} exited {proc.returncode}:\n{proc.stderr[:2000]}",
              file=sys.stderr)

    try:
        return json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError:
        print(f"WARNING: could not parse JSON output of {plugin}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Heuristic scoring
# ---------------------------------------------------------------------------

# Processes that legitimately run with no parent / unusual ancestry on
# Windows. Anything NOT in this allow-list that has a suspicious parent
# chain gets flagged harder. This is intentionally small — extend it for
# your environment's baseline.
KNOWN_ROOT_PROCESSES = {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe"}

# malfind already restricts itself to RWX/suspicious regions, so any row
# it returns is inherently noteworthy. We still score it so the UI can
# sort/prioritize instead of just listing everything as "equally bad".
def score_malfind_hit(hit: dict) -> int:
    score = 50  # baseline: malfind flagged it at all
    protection = str(hit.get("Protection", ""))
    if "EXECUTE_READWRITE" in protection:
        score += 30
    disasm = str(hit.get("Disasm", "")) + str(hit.get("Hexdump", ""))
    # MZ header inside a private, executable allocation is a classic
    # reflectively-loaded / manually-mapped module indicator.
    if "4d 5a" in disasm.lower() or "MZ" in disasm:
        score += 20
    return min(score, 100)


def score_process(proc: dict, pslist_pids: set, psscan_pids: set) -> dict:
    """
    Cross-references pslist (walks the kernel's active EPROCESS linked
    list) against psscan (pool-tag scans physical memory for EPROCESS
    structures regardless of list linkage). A PID present in psscan but
    absent from pslist is a classic DKOM/unlinking indicator -- the
    process was hidden from the live list but its structure is still
    physically present in memory.
    """
    pid = proc.get("PID")
    flags = []
    score = 0

    if pid in psscan_pids and pid not in pslist_pids:
        flags.append("hidden_from_pslist (present in psscan only)")
        score += 60

    ppid = proc.get("PPID")
    name = str(proc.get("ImageFileName", "")).lower()
    if name not in KNOWN_ROOT_PROCESSES and ppid in (0, None):
        flags.append("orphaned_process (no valid parent)")
        score += 25

    return {"pid": pid, "name": proc.get("ImageFileName"), "ppid": ppid,
            "flags": flags, "score": min(score, 100)}


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def analyze(image_path: str) -> dict:
    print(f"[*] Running windows.pslist on {image_path} ...", file=sys.stderr)
    pslist = run_vol_plugin(image_path, "windows.pslist")

    print("[*] Running windows.psscan ...", file=sys.stderr)
    psscan = run_vol_plugin(image_path, "windows.psscan")

    print("[*] Running windows.malfind ...", file=sys.stderr)
    malfind = run_vol_plugin(image_path, "windows.malfind")

    pslist_pids = {row.get("PID") for row in pslist}
    psscan_pids = {row.get("PID") for row in psscan}

    process_findings = [
        score_process(row, pslist_pids, psscan_pids) for row in psscan
    ]
    process_findings = [f for f in process_findings if f["score"] > 0]

    malfind_findings = []
    for hit in malfind:
        entry = {
            "pid": hit.get("PID"),
            "process": hit.get("Process"),
            "start_vpn": hit.get("Start VPN"),
            "protection": hit.get("Protection"),
            "score": score_malfind_hit(hit),
        }
        malfind_findings.append(entry)

    report = {
        "image": image_path,
        "summary": {
            "total_processes_pslist": len(pslist),
            "total_processes_psscan": len(psscan),
            "hidden_process_count": sum(
                1 for f in process_findings if "hidden_from_pslist" in " ".join(f["flags"])
            ),
            "malfind_hit_count": len(malfind_findings),
        },
        "process_findings": sorted(process_findings, key=lambda f: -f["score"]),
        "malfind_findings": sorted(malfind_findings, key=lambda f: -f["score"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Volatility3-based memory anomaly scanner")
    parser.add_argument("--image", required=True, help="Path to .raw/.vmem memory image")
    parser.add_argument("--out", default="report.json", help="Where to write the JSON report")
    args = parser.parse_args()

    if not Path(args.image).exists():
        print(f"ERROR: image not found: {args.image}", file=sys.stderr)
        sys.exit(1)

    report = analyze(args.image)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report written to {args.out}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
