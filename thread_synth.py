#!/usr/bin/env python3
"""
thread_synth.py
---------------
SYNTHETIC generator for thread_binding.py output, so the synthetic demo
chain can also show the "Hashing Threads" dashboard section WITHOUT a real
memory dump. (thread_binding.py itself only extracts from a real dump via
Volatility; this mirrors synthesize_report.py / netscan_synth.py.)

HONESTY: this fabricates the thread verdicts -- it is PIPELINE VALIDATION
only, not detection. Real results come from thread_binding.py on a dump.

Usage:
    python thread_synth.py --report report.json --out thread_findings.json
"""

import argparse
import json
import random


def load_candidate_pids(report_path):
    with open(report_path) as f:
        report = json.load(f)
    pids = []
    for section in ("malfind_findings", "process_findings"):
        for row in report.get(section, []):
            if row.get("pid") is not None:
                pids.append((row["pid"], row.get("process") or row.get("name") or "?"))
    return pids or [(4444, "proc.exe")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--out", default="thread_findings.json")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    cands = load_candidate_pids(args.report)
    findings = []

    # 1 bound HASHING_THREAD on a flagged process (unbacked + high CPU)
    pid, name = cands[0]
    findings.append({
        "pid": pid, "tid": 99, "process": name,
        "start_address": hex(random.randint(0x10000000, 0x3FFFFFFF)),
        "cycle_time": random.randint(1_200_000_000, 1_800_000_000),
        "unbacked": True, "high_cpu": True, "verdict": "HASHING_THREAD",
        "score": 100,
        "reasons": ["thread start address in unbacked/private executable memory",
                    "abnormal CPU cycle consumption",
                    "BOUND: unbacked execution + high CPU on the same thread"],
    })
    # 1 injected-but-idle thread (unbacked, low CPU) -> NOT mining
    if len(cands) > 1:
        pid2, name2 = cands[1]
        findings.append({
            "pid": pid2, "tid": 50, "process": name2,
            "start_address": hex(random.randint(0x10000000, 0x3FFFFFFF)),
            "cycle_time": random.randint(800_000, 2_000_000),
            "unbacked": True, "high_cpu": False, "verdict": "injected_thread",
            "score": 50,
            "reasons": ["thread start address in unbacked/private executable memory"],
        })

    with open(args.out, "w") as f:
        json.dump({"hashing_thread_findings": findings}, f, indent=2)
    print(f"[+] Wrote {len(findings)} synthetic thread findings to {args.out}")


if __name__ == "__main__":
    main()
