#!/usr/bin/env python3
"""
synthesize_report.py
---------------------
Generates a fake report.json in the exact schema that heuristic_analyzer.py
produces, so you can build/demo/test streamlit_app.py without ever running
Volatility3 or touching a real (or simulated) attack.

Usage:
    python synthesize_report.py --out report.json
    python synthesize_report.py --out report.json --seed 42 --num-hidden 3
"""

import argparse
import json
import random

NORMAL_PROCESSES = [
    "System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe",
    "winword.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "RuntimeBroker.exe",
]

# Names that *sound* legitimate but are common malware masquerade targets —
# good for synthetic "flagged" entries since they mimic real incidents
# without being tied to any specific real sample.
SUSPICIOUS_NAMES = [
    "svch0st.exe", "scvhost.exe", "rundll32.exe", "update_helper.exe",
    "winlogon32.exe", "taskhost_svc.exe",
]


def make_clean_process(pid_pool):
    pid = pid_pool.pop()
    name = random.choice(NORMAL_PROCESSES)
    ppid = random.choice([4, 400, 500, 600]) if name != "System" else 0
    return {"PID": pid, "ImageFileName": name, "PPID": ppid}


def synthesize(num_clean=25, num_hidden=2, num_malfind=4, seed=None) -> dict:
    if seed is not None:
        random.seed(seed)

    pid_pool = list(range(4000, 9000))
    random.shuffle(pid_pool)

    pslist = [make_clean_process(pid_pool) for _ in range(num_clean)]
    pslist_pids = {p["PID"] for p in pslist}

    # psscan = everything in pslist PLUS some "hidden" processes that were
    # unlinked from the live list (present in pool scan, absent from pslist)
    psscan = list(pslist)
    hidden_entries = []
    for _ in range(num_hidden):
        pid = pid_pool.pop()
        name = random.choice(SUSPICIOUS_NAMES)
        entry = {"PID": pid, "ImageFileName": name, "PPID": random.choice([None, 0])}
        psscan.append(entry)
        hidden_entries.append(entry)

    # Build process_findings the way heuristic_analyzer.py's scoring would
    process_findings = []
    for entry in hidden_entries:
        flags = ["hidden_from_pslist (present in psscan only)"]
        score = 60
        if entry["PPID"] in (0, None):
            flags.append("orphaned_process (no valid parent)")
            score += 25
        process_findings.append({
            "pid": entry["PID"], "name": entry["ImageFileName"],
            "ppid": entry["PPID"], "flags": flags, "score": min(score, 100),
        })

    # Synthetic malfind hits — RWX regions attributed to a mix of hidden
    # and (for realism) occasionally a normal-looking process name
    malfind_findings = []
    candidates = hidden_entries + random.sample(pslist, k=min(2, len(pslist)))
    for i in range(num_malfind):
        src = candidates[i % len(candidates)]
        has_mz = random.random() > 0.4
        score = 50 + (30 if True else 0) + (20 if has_mz else 0)
        malfind_findings.append({
            "pid": src["PID"],
            "process": src["ImageFileName"],
            "start_vpn": hex(random.randint(0x10000000, 0x7FFFFFFF)),
            "protection": "PAGE_EXECUTE_READWRITE",
            "score": min(score, 100),
        })

    report = {
        "image": "synthetic://generated-sample",
        "summary": {
            "total_processes_pslist": len(pslist),
            "total_processes_psscan": len(psscan),
            "hidden_process_count": len(hidden_entries),
            "malfind_hit_count": len(malfind_findings),
        },
        "process_findings": sorted(process_findings, key=lambda f: -f["score"]),
        "malfind_findings": sorted(malfind_findings, key=lambda f: -f["score"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic report.json for dashboard testing")
    parser.add_argument("--out", default="report.json")
    parser.add_argument("--num-clean", type=int, default=25, help="Number of normal processes")
    parser.add_argument("--num-hidden", type=int, default=2, help="Number of hidden/unlinked processes")
    parser.add_argument("--num-malfind", type=int, default=4, help="Number of synthetic malfind hits")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    args = parser.parse_args()

    report = synthesize(args.num_clean, args.num_hidden, args.num_malfind, args.seed)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Synthetic report written to {args.out}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
