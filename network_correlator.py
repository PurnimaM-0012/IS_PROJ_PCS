#!/usr/bin/env python3
"""
network_correlator.py
-----------------------
Joins windows.netscan rows (which PID owns which connection) against flow
stats in SQLite (what that connection's traffic actually looked like), and
scores each match against a cryptojacking/mining heuristic.

Works identically whether flows.db was built by pcap_to_sqlite.py (real
capture) or flow_synth.py (synthetic) -- same schema either way.

Usage:
    python network_correlator.py --netscan netscan.json --db flows.db \
        --out network_findings.json
"""

import argparse
import json
import sqlite3

MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 14433}
MINING_DOMAIN_SUBSTRINGS = ["pool", "xmr", "monero", "nicehash", "stratum"]

DURATION_THRESHOLD_SECONDS = 300   # >5 min continuous connection
MAX_AVG_PACKET_SIZE = 300          # small, uniform Stratum-like messages
PPM_STEADY_MIN = 5                 # steady low-frequency heartbeat range
PPM_STEADY_MAX = 30


def lookup_flow(cursor, dst_ip, dst_port):
    cursor.execute(
        "SELECT packet_count, total_bytes, avg_packet_size, duration_seconds, "
        "packets_per_minute FROM flows WHERE dst_ip = ? AND dst_port = ?",
        (dst_ip, dst_port),
    )
    return cursor.fetchone()


def score_connection(conn_row, flow_row) -> dict:
    score = 0
    flags = []

    port = conn_row.get("ForeignPort")
    domain = str(conn_row.get("ForeignDomain", "")).lower()

    if port in MINING_PORTS:
        score += 40
        flags.append(f"known_mining_port ({port})")
    if any(sub in domain for sub in MINING_DOMAIN_SUBSTRINGS):
        score += 40
        flags.append(f"mining_domain_pattern ({domain})")

    if flow_row:
        packet_count, total_bytes, avg_size, duration, ppm = flow_row

        if duration >= DURATION_THRESHOLD_SECONDS:
            score += 30
            flags.append(f"long_lived_connection ({duration:.0f}s)")

        if avg_size <= MAX_AVG_PACKET_SIZE:
            score += 20
            flags.append(f"small_uniform_packets (avg {avg_size:.0f}B)")

        if PPM_STEADY_MIN <= ppm <= PPM_STEADY_MAX:
            score += 10
            flags.append(f"steady_heartbeat ({ppm:.1f} pkt/min)")

    return {"score": min(score, 100), "flags": flags, "flow": flow_row}


def correlate(netscan_path, db_path):
    with open(netscan_path) as f:
        connections = json.load(f)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    findings = []
    for row in connections:
        dst_ip = row.get("ForeignAddr")
        dst_port = row.get("ForeignPort")
        flow_row = lookup_flow(cur, dst_ip, dst_port)

        result = score_connection(row, flow_row)
        if result["score"] == 0:
            continue  # no evidence either way, skip

        entry = {
            "pid": row.get("PID"),
            "process": row.get("Owner"),
            "foreign_ip": dst_ip,
            "foreign_port": dst_port,
            "foreign_domain": row.get("ForeignDomain"),
            "score": result["score"],
            "flags": result["flags"],
        }
        if result["flow"]:
            (packet_count, total_bytes, avg_size, duration, ppm) = result["flow"]
            entry.update({
                "duration_seconds": round(duration, 1),
                "avg_packet_size": round(avg_size, 1),
                "packets_per_minute": round(ppm, 1),
            })
        findings.append(entry)

    conn.close()
    return sorted(findings, key=lambda f: -f["score"])


def main():
    parser = argparse.ArgumentParser(description="Correlate netscan connections with flow stats")
    parser.add_argument("--netscan", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", default="network_findings.json")
    args = parser.parse_args()

    findings = correlate(args.netscan, args.db)

    with open(args.out, "w") as f:
        json.dump({"network_findings": findings}, f, indent=2)

    print(f"[+] Wrote {len(findings)} network findings to {args.out}")
    for f_entry in findings[:5]:
        print(f"    PID {f_entry['pid']} ({f_entry['process']}) -> "
              f"{f_entry['foreign_ip']}:{f_entry['foreign_port']} "
              f"score={f_entry['score']}")


if __name__ == "__main__":
    main()
