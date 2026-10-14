#!/usr/bin/env python3
"""
flow_synth.py
--------------
Generates synthetic network flow records -- matching the exact SQLite
schema that pcap_to_sqlite.py produces from a real PCAP -- so the rest of
the pipeline (network_correlator.py, the dashboard) works identically
whether the data came from a real capture or not.

Reads netscan.json (from netscan_synth.py) so that flows line up with the
same ForeignAddr/ForeignPort pairs already assigned to PIDs.

Usage:
    python flow_synth.py --netscan netscan.json --db flows.db
"""

import argparse
import json
import random
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    src_ip TEXT, src_port INTEGER,
    dst_ip TEXT, dst_port INTEGER,
    packet_count INTEGER,
    total_bytes INTEGER,
    avg_packet_size REAL,
    duration_seconds REAL,
    packets_per_minute REAL
);
"""

MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 14433}


def make_mining_flow(src_ip, src_port, dst_ip, dst_port):
    """Long-lived, steady, small-packet flow -- Stratum-like fingerprint."""
    duration = random.uniform(600, 3600)       # 10-60 min, continuous
    ppm = random.uniform(8, 20)                # steady low-frequency heartbeat
    packet_count = int((duration / 60) * ppm)
    avg_size = random.uniform(80, 280)         # small, uniform JSON-RPC messages
    total_bytes = int(packet_count * avg_size)
    return (src_ip, src_port, dst_ip, dst_port, packet_count,
            total_bytes, avg_size, duration, ppm)


def make_normal_flow(src_ip, src_port, dst_ip, dst_port):
    """Bursty, short-lived, variable packet size -- ordinary web traffic."""
    duration = random.uniform(2, 45)           # short-lived
    packet_count = random.randint(5, 80)
    ppm = packet_count / (duration / 60) if duration > 0 else packet_count
    avg_size = random.uniform(300, 1400)       # variable, larger (web payloads)
    total_bytes = int(packet_count * avg_size)
    return (src_ip, src_port, dst_ip, dst_port, packet_count,
            total_bytes, avg_size, duration, ppm)


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic flow records into SQLite")
    parser.add_argument("--netscan", required=True, help="netscan.json from netscan_synth.py")
    parser.add_argument("--db", default="flows.db")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    with open(args.netscan) as f:
        connections = json.load(f)

    rows = []
    for conn_row in connections:
        src_ip = conn_row["LocalAddr"]
        src_port = conn_row["LocalPort"]
        dst_ip = conn_row["ForeignAddr"]
        dst_port = conn_row["ForeignPort"]

        if dst_port in MINING_PORTS:
            rows.append(make_mining_flow(src_ip, src_port, dst_ip, dst_port))
        else:
            rows.append(make_normal_flow(src_ip, src_port, dst_ip, dst_port))

    conn = sqlite3.connect(args.db)
    conn.execute(SCHEMA)
    conn.execute("DELETE FROM flows")
    conn.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()

    print(f"[+] Wrote {len(rows)} synthetic flows to {args.db}")


if __name__ == "__main__":
    main()
