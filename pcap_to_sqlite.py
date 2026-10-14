#!/usr/bin/env python3
"""
pcap_to_sqlite.py
------------------
Parses a real .pcap/.pcapng capture with Pyshark, aggregates packets into
flows (same 4-tuple: src_ip, src_port, dst_ip, dst_port), and writes the
flow-level stats into a SQLite database. This is the "PCAP to SQLITE"
deliverable, used when you have an actual capture instead of synthetic data.

Requirements:
    pip install pyshark
    (pyshark wraps tshark -- install Wireshark/tshark on the host too)

Usage:
    python pcap_to_sqlite.py --pcap capture.pcap --db flows.db
"""

import argparse
import sqlite3
from collections import defaultdict

import pyshark

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


def extract_flows(pcap_path):
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    flows = defaultdict(lambda: {"sizes": [], "timestamps": []})

    for pkt in cap:
        try:
            if "IP" not in pkt or not hasattr(pkt, "transport_layer"):
                continue
            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            layer = pkt.transport_layer
            if layer is None:
                continue
            src_port = int(pkt[layer].srcport)
            dst_port = int(pkt[layer].dstport)
            length = int(pkt.length)
            ts = float(pkt.sniff_timestamp)
        except (AttributeError, ValueError):
            continue

        key = (src_ip, src_port, dst_ip, dst_port)
        flows[key]["sizes"].append(length)
        flows[key]["timestamps"].append(ts)

    cap.close()
    return flows


def flows_to_rows(flows):
    rows = []
    for (src_ip, src_port, dst_ip, dst_port), data in flows.items():
        sizes = data["sizes"]
        timestamps = sorted(data["timestamps"])
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        packet_count = len(sizes)
        total_bytes = sum(sizes)
        avg_size = total_bytes / packet_count if packet_count else 0
        ppm = (packet_count / (duration / 60)) if duration > 0 else packet_count

        rows.append((src_ip, src_port, dst_ip, dst_port, packet_count,
                      total_bytes, avg_size, duration, ppm))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Extract flow stats from a PCAP into SQLite")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--db", default="flows.db")
    args = parser.parse_args()

    flows = extract_flows(args.pcap)
    rows = flows_to_rows(flows)

    conn = sqlite3.connect(args.db)
    conn.execute(SCHEMA)
    conn.execute("DELETE FROM flows")  # fresh run each time
    conn.executemany(
        "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    conn.close()

    print(f"[+] Wrote {len(rows)} flows to {args.db}")


if __name__ == "__main__":
    main()
