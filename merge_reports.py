#!/usr/bin/env python3
"""
merge_reports.py
-----------------
Combines report.json (process_findings + malfind_findings) with
network_findings.json into one final_report.json for the dashboard.

If a PID appears in both the memory-side findings AND the network
findings, that's the strongest possible signal (memory anomaly + mining
traffic pattern on the same process) -- this script boosts both entries'
scores when that overlap happens.

Usage:
    python merge_reports.py --report report.json \
        --network network_findings.json --out final_report.json
"""

"""import argparse
import json

CROSS_CATEGORY_BOOST = 20


def merge(report_path, network_path):
    with open(report_path) as f:
        report = json.load(f)
    with open(network_path) as f:
        network = json.load(f)

    network_findings = network.get("network_findings", [])
    report["network_findings"] = network_findings

    memory_pids = {row["pid"] for row in report.get("process_findings", [])}
    memory_pids |= {row["pid"] for row in report.get("malfind_findings", [])}
    network_pids = {row["pid"] for row in network_findings}

    overlap = memory_pids & network_pids

    for row in report.get("process_findings", []):
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)
            row["flags"].append("cross_category_match (memory + network)")

    for row in report.get("malfind_findings", []):
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)

    for row in network_findings:
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)
            row["flags"].append("cross_category_match (memory + network)")

    report["summary"]["network_hit_count"] = len(network_findings)
    report["summary"]["cross_category_match_count"] = len(overlap)

    return report


def main():
    parser = argparse.ArgumentParser(description="Merge memory and network findings into one report")
    parser.add_argument("--report", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--out", default="final_report.json")
    args = parser.parse_args()

    merged = merge(args.report, args.network)

    with open(args.out, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"[+] Merged report written to {args.out}")
    print(json.dumps(merged["summary"], indent=2))


if __name__ == "__main__":
    main()"""
#!/usr/bin/env python3
"""
merge_reports.py
-----------------
Combines report.json (process_findings + malfind_findings) with
network_findings.json AND thread_findings.json (Option 2: thread-level
CPU<->unbacked-memory binding) into one final_report.json for the dashboard.

Cross-signal boost: a PID that shows up across categories (memory anomaly
+ mining network pattern + a bound hashing thread) is the strongest
possible cryptojacking signal, so overlapping entries get a score boost.

Usage:
    python merge_reports.py --report report.json \
        --network network_findings.json \
        --threads thread_findings.json \
        --out final_report.json

--threads is OPTIONAL: omit it and the pipeline behaves exactly as before.
"""

import argparse
import json

CROSS_CATEGORY_BOOST = 20


def merge(report_path, network_path, threads_path=None):
    with open(report_path) as f:
        report = json.load(f)
    with open(network_path) as f:
        network = json.load(f)

    network_findings = network.get("network_findings", [])
    report["network_findings"] = network_findings

    # --- NEW: thread-level hashing-thread findings (Option 2) ---
    hashing_findings = []
    if threads_path:
        with open(threads_path) as f:
            hashing_findings = json.load(f).get("hashing_thread_findings", [])
    report["hashing_thread_findings"] = hashing_findings

    # PIDs flagged on each axis
    memory_pids = {row["pid"] for row in report.get("process_findings", [])}
    memory_pids |= {row["pid"] for row in report.get("malfind_findings", [])}
    network_pids = {row["pid"] for row in network_findings}
    # a bound hashing thread is strong MEMORY evidence too:
    hashing_pids = {row["pid"] for row in hashing_findings}
    memory_pids |= hashing_pids

    overlap = memory_pids & network_pids

    for row in report.get("process_findings", []):
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)
            row["flags"].append("cross_category_match (memory + network)")

    for row in report.get("malfind_findings", []):
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)

    for row in network_findings:
        if row["pid"] in overlap:
            row["score"] = min(row["score"] + CROSS_CATEGORY_BOOST, 100)
            row["flags"].append("cross_category_match (memory + network)")

    # A hashing thread whose PID also has mining traffic = near-certain
    # cryptojacking -> boost those thread entries too.
    for row in hashing_findings:
        if row["pid"] in network_pids:
            row["score"] = min(row.get("score", 0) + CROSS_CATEGORY_BOOST, 100)
            row.setdefault("reasons", []).append(
                "cross_category_match (hashing thread + mining traffic)")

    report["summary"]["network_hit_count"] = len(network_findings)
    report["summary"]["hashing_thread_count"] = len(hashing_findings)
    report["summary"]["cross_category_match_count"] = len(overlap)
    return report


def main():
    parser = argparse.ArgumentParser(description="Merge memory + network + thread findings")
    parser.add_argument("--report", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--threads", default=None,
                        help="thread_findings.json from thread_binding.py (optional)")
    parser.add_argument("--out", default="final_report.json")
    args = parser.parse_args()

    merged = merge(args.report, args.network, args.threads)
    with open(args.out, "w") as f:
        json.dump(merged, f, indent=2)
    print(f"[+] Merged report written to {args.out}")
    print(json.dumps(merged["summary"], indent=2))


if __name__ == "__main__":
    main()
