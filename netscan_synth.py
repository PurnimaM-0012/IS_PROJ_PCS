#!/usr/bin/env python3
"""
netscan_synth.py
-----------------
Generates synthetic windows.netscan rows (the memory-resident connection
table Volatility3 would normally extract) and ties them to PIDs that
already exist in a report.json produced by synthesize_report.py.

Usage:
    python netscan_synth.py --report report.json --out netscan.json \
        --num-mining 2 --num-normal 6
"""

import argparse
import json
import random

# Known Stratum / mining-pool ports and domain substrings used as ground
# truth for which synthetic connections get built to "look like" mining.
MINING_PORTS = [3333, 4444, 5555, 7777, 14444, 14433]
MINING_DOMAINS = ["pool.supportxmr.com", "xmr.nanopool.org",
                   "gulf.moneroocean.stream", "pool.hashvault.pro"]

NORMAL_PORTS = [443, 80, 8080, 993]
NORMAL_DOMAINS = ["google.com", "microsoft.com", "akamai.net",
                   "cloudfront.net", "office365.com"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def load_candidate_pids(report_path):
    with open(report_path) as f:
        report = json.load(f)
    pids = set()
    for section in ("process_findings", "malfind_findings"):
        for row in report.get(section, []):
            if row.get("pid") is not None:
                pids.add((row["pid"], row.get("name") or row.get("process")))
    # Fall back to some generic PIDs if the report had no findings at all
    if not pids:
        pids = {(4000 + i, f"proc{i}.exe") for i in range(5)}
    return list(pids)


def make_connection(pid, name, mining: bool):
    if mining:
        port = random.choice(MINING_PORTS)
        domain = random.choice(MINING_DOMAINS)
    else:
        port = random.choice(NORMAL_PORTS)
        domain = random.choice(NORMAL_DOMAINS)
    return {
        "PID": pid,
        "Owner": name,
        "LocalAddr": "10.0.0.5",
        "LocalPort": random.randint(49152, 65535),
        "ForeignAddr": random_ip(),
        "ForeignPort": port,
        "ForeignDomain": domain,  # not a real volatility field, added for
                                  # correlation convenience in this project
        "State": "ESTABLISHED",
    }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic windows.netscan rows")
    parser.add_argument("--report", required=True, help="Existing report.json to source PIDs from")
    parser.add_argument("--out", default="netscan.json")
    parser.add_argument("--num-mining", type=int, default=2,
                         help="Number of connections to flavor as mining-like")
    parser.add_argument("--num-normal", type=int, default=6,
                         help="Number of ordinary background connections")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    candidates = load_candidate_pids(args.report)
    connections = []

    for i in range(args.num_mining):
        pid, name = candidates[i % len(candidates)]
        connections.append(make_connection(pid, name, mining=True))

    for i in range(args.num_normal):
        pid, name = candidates[(i + args.num_mining) % len(candidates)]
        connections.append(make_connection(pid, name, mining=False))

    with open(args.out, "w") as f:
        json.dump(connections, f, indent=2)

    print(f"[+] Wrote {len(connections)} synthetic netscan rows to {args.out}")


if __name__ == "__main__":
    main()
