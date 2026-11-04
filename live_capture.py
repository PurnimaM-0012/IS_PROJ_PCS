#!/usr/bin/env python3
"""
live_capture.py
----------------
Captures LIVE network traffic on this machine and packages it for the
cryptojacking dashboard. Run it locally, then upload the output JSON in
the Streamlit app ("Live network capture" mode).

What it collects during the capture window:
  * packets   -> via tshark, aggregated into flows (same stats/schema as
                 pcap_to_sqlite.py)
  * PID map   -> psutil polled every second: which process owns which
                 connection. This is the live equivalent of
                 windows.netscan from a memory dump.
  * domains   -> DNS answers + TLS SNI seen in the capture, so the
                 mining-domain heuristic still works on real traffic.

Scoring reuses network_correlator.score_connection, so live findings are
judged by exactly the same heuristic as the rest of the pipeline.

Requirements:
    Wireshark/tshark (+ Npcap on Windows), pip install psutil
    Capture permission: Npcap installed without "admin only" mode, or run
    as Administrator / root.

Usage:
    python live_capture.py --list-interfaces
    python live_capture.py --interface "Wi-Fi" --duration 360 \
        --out live_capture.json [--pcap keep.pcap] [--findings-out network_findings.json]

Note: the "long_lived_connection" heuristic needs a flow to be observed
for >= 300s, so capture for at least ~6 minutes to give it a chance to fire.
"""

import argparse
import ipaddress
import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone

from network_correlator import (DURATION_THRESHOLD_SECONDS, correlate_connections,
                                score_connection)
from pcap_to_sqlite import SCHEMA, flows_to_rows

FLOW_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "packet_count",
                "total_bytes", "avg_packet_size", "duration_seconds",
                "packets_per_minute"]

_TSHARK_FALLBACKS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"D:\wireshark\tshark.exe",
    "/usr/bin/tshark", "/usr/local/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
]


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------

def find_tshark(explicit=None):
    """Return a usable tshark path, or None."""
    for cand in [explicit, os.environ.get("TSHARK"), shutil.which("tshark"),
                 *_TSHARK_FALLBACKS]:
        if cand and os.path.isfile(cand):
            return cand
    return None


def list_interfaces(tshark):
    """[(id, label)] from `tshark -D`; id is what -i accepts."""
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                         timeout=30).stdout
    result = []
    for line in out.splitlines():
        # "5. \Device\NPF_{...} (Wi-Fi)"
        _, _, rest = line.partition(". ")
        if not rest:
            continue
        dev, _, label = rest.partition(" (")
        label = label.rstrip(")") or dev
        result.append((dev.strip(), label))
    return result


def _tshark_fields(tshark, pcap, display_filter, fields):
    cmd = [tshark, "-r", pcap, "-n", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
    for line in out.splitlines():
        yield line.split("\t")


# ---------------------------------------------------------------------------
# PCAP -> flows / domains   (tshark field export; much faster than pyshark)
# ---------------------------------------------------------------------------

def extract_flows_fast(tshark, pcap):
    """Same aggregation as pcap_to_sqlite.extract_flows (per 4-tuple,
    per direction), IPv4 + IPv6, TCP + UDP."""
    flows = defaultdict(lambda: {"sizes": [], "timestamps": []})
    packets = 0
    fields = ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
              "frame.len", "frame.time_epoch"]
    for cols in _tshark_fields(tshark, pcap, "tcp or udp", fields):
        packets += 1
        cols += [""] * (len(fields) - len(cols))
        ip4s, ip4d, ip6s, ip6d, tsp, tdp, usp, udp_, length, ts = cols
        src, dst = (ip4s, ip4d) if ip4s else (ip6s, ip6d)
        sport, dport = (tsp, tdp) if tsp else (usp, udp_)
        try:
            key = (src, int(sport), dst, int(dport))
            flows[key]["sizes"].append(int(length))
            flows[key]["timestamps"].append(float(ts))
        except ValueError:
            continue
    return flows, packets


def extract_domains(tshark, pcap):
    """{ip: domain} from DNS A/AAAA answers and TLS SNI (SNI wins)."""
    domains = {}
    for cols in _tshark_fields(tshark, pcap, "dns.flags.response == 1",
                               ["dns.qry.name", "dns.a", "dns.aaaa"]):
        if not cols or not cols[0]:
            continue
        name = cols[0]
        for ips in cols[1:]:
            for ip in filter(None, ips.split(",")):
                domains.setdefault(ip, name)
    for cols in _tshark_fields(tshark, pcap, "tls.handshake.extensions_server_name",
                               ["ip.dst", "ipv6.dst",
                                "tls.handshake.extensions_server_name"]):
        if len(cols) >= 3 and cols[2]:
            domains[cols[0] or cols[1]] = cols[2]
    return domains


def rows_to_dicts(rows):
    return [dict(zip(FLOW_COLUMNS, r)) for r in rows]


def parse_pcap(tshark, pcap):
    """pcap -> (flows as dicts, domain map, packet count)."""
    flows, packets = extract_flows_fast(tshark, pcap)
    return rows_to_dicts(flows_to_rows(flows)), extract_domains(tshark, pcap), packets


# ---------------------------------------------------------------------------
# Live PID <-> connection map (psutil) -- live stand-in for windows.netscan
# ---------------------------------------------------------------------------

class ConnectionTracker:
    def __init__(self):
        import psutil  # imported lazily so pcap-only use doesn't need it
        self.psutil = psutil
        self.conns = {}
        self._names = {}

    def _name(self, pid):
        if pid not in self._names:
            try:
                self._names[pid] = self.psutil.Process(pid).name()
            except Exception:
                self._names[pid] = "unknown"
        return self._names[pid]

    def poll(self):
        now = time.time()
        try:
            snapshot = self.psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in snapshot:
            if not c.raddr or not c.pid:
                continue
            key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
            entry = self.conns.get(key)
            if entry is None:
                self.conns[key] = {
                    "PID": c.pid, "Owner": self._name(c.pid),
                    "Proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "LocalAddr": c.laddr.ip, "LocalPort": c.laddr.port,
                    "ForeignAddr": c.raddr.ip, "ForeignPort": c.raddr.port,
                    "State": c.status, "first_seen": now, "last_seen": now,
                }
            else:
                entry["State"] = c.status
                entry["last_seen"] = now

    def rows(self):
        return list(self.conns.values())


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def run_capture(tshark, interface, duration, pcap_path, progress=None):
    """Capture `duration` seconds on `interface` into pcap_path while
    tracking PID ownership. Returns (connection rows, tshark stderr)."""
    tracker = ConnectionTracker()
    cmd = [tshark, "-i", interface, "-a", f"duration:{duration}",
           "-F", "pcap", "-w", pcap_path, "-q"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    start = time.time()
    try:
        while proc.poll() is None:
            tracker.poll()
            if progress:
                progress(min(time.time() - start, duration), duration)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted -- stopping capture and keeping what we have.")
        proc.terminate()
    proc.wait()
    tracker.poll()
    err = proc.stderr.read() if proc.stderr else ""
    if proc.returncode not in (0, None) and not os.path.exists(pcap_path):
        raise RuntimeError(f"tshark failed (exit {proc.returncode}): {err.strip()}")
    return tracker.rows(), err


def build_capture(tshark, interface, duration, keep_pcap=None, progress=None):
    """Full live capture -> dict ready to json.dump (the upload format)."""
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tmpdir = tempfile.mkdtemp(prefix="livecap_")
    pcap = keep_pcap or os.path.join(tmpdir, "capture.pcap")
    try:
        connections, _ = run_capture(tshark, interface, duration, pcap, progress)
        flows, domains, packets = parse_pcap(tshark, pcap)
    finally:
        if not keep_pcap:
            shutil.rmtree(tmpdir, ignore_errors=True)

    for c in connections:
        c["ForeignDomain"] = domains.get(c["ForeignAddr"], "")

    return {
        "capture_meta": {
            "source": "live_capture",
            "host": platform.node(),
            "interface": interface,
            "requested_duration_seconds": duration,
            "started_utc": started,
            "packet_count": packets,
            "flow_count": len(flows),
            "connection_count": len(connections),
        },
        "connections": connections,
        "flows": flows,
        "domains": domains,
    }


# ---------------------------------------------------------------------------
# Analysis (shared by CLI and the Streamlit live view)
# ---------------------------------------------------------------------------

def _is_client_to_server(flow):
    """Heuristic direction for flows with no PID info: the side with the
    lower port is the server, so keep flows heading to it."""
    return flow["dst_port"] <= flow["src_port"]


def analyze_capture(capture):
    """Score a capture dict. Returns findings in network_findings.json
    format: PID-attributed connections first, then outbound flows that no
    tracked process owned (pid None) -- e.g. from a pcap-only upload."""
    flows = capture.get("flows", [])
    connections = capture.get("connections", [])
    domains = capture.get("domains", {})

    db = sqlite3.connect(":memory:")
    db.execute(SCHEMA)
    db.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?)",
                   [tuple(f[c] for c in FLOW_COLUMNS) for f in flows])
    findings = correlate_connections(connections, db.cursor())
    db.close()

    owned = {(c["ForeignAddr"], c["ForeignPort"]) for c in connections}
    for f in flows:
        if (f["dst_ip"], f["dst_port"]) in owned or not _is_client_to_server(f):
            continue
        try:
            if ipaddress.ip_address(f["dst_ip"]).is_multicast:
                continue
        except ValueError:
            pass
        domain = domains.get(f["dst_ip"], "")
        flow_row = (f["packet_count"], f["total_bytes"], f["avg_packet_size"],
                    f["duration_seconds"], f["packets_per_minute"])
        result = score_connection({"ForeignPort": f["dst_port"],
                                   "ForeignDomain": domain}, flow_row)
        if result["score"] == 0:
            continue
        findings.append({
            "pid": None, "process": "(unattributed)",
            "foreign_ip": f["dst_ip"], "foreign_port": f["dst_port"],
            "foreign_domain": domain,
            "score": result["score"], "flags": result["flags"],
            "duration_seconds": round(f["duration_seconds"], 1),
            "avg_packet_size": round(f["avg_packet_size"], 1),
            "packets_per_minute": round(f["packets_per_minute"], 1),
        })

    return sorted(findings, key=lambda x: -x["score"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Live network capture for the cryptojacking dashboard")
    p.add_argument("--list-interfaces", action="store_true")
    p.add_argument("--interface", "-i", help="interface name/ID from --list-interfaces (e.g. Wi-Fi)")
    p.add_argument("--duration", "-d", type=int, default=360, help="seconds (default 360)")
    p.add_argument("--out", default="live_capture.json")
    p.add_argument("--pcap", help="also keep the raw pcap at this path")
    p.add_argument("--findings-out", help="also write network_findings.json (merge_reports.py format)")
    p.add_argument("--tshark", help="path to tshark if it's not on PATH")
    p.add_argument("--progress-file", help=argparse.SUPPRESS)  # used by the Streamlit button
    args = p.parse_args()

    tshark = find_tshark(args.tshark)
    if not tshark:
        sys.exit("[-] tshark not found. Install Wireshark (with Npcap on Windows) "
                 "or pass --tshark PATH.")

    if args.list_interfaces:
        for i, (dev, label) in enumerate(list_interfaces(tshark), 1):
            print(f"{i:>2}. {label:<45} {dev}")
        return
    if not args.interface:
        p.error("--interface is required (see --list-interfaces)")

    if args.duration < DURATION_THRESHOLD_SECONDS:
        print(f"[!] Duration {args.duration}s < {DURATION_THRESHOLD_SECONDS}s: the "
              "long_lived_connection heuristic cannot fire in this window.")

    def progress(elapsed, total):
        if args.progress_file:
            try:
                with open(args.progress_file, "w") as fh:
                    fh.write(f"{elapsed:.0f} {total}")
            except OSError:
                pass
        print(f"\r[*] Capturing on {args.interface}: {elapsed:4.0f}/{total}s", end="", flush=True)

    try:
        capture = build_capture(tshark, args.interface, args.duration,
                                keep_pcap=args.pcap, progress=progress)
    except RuntimeError as exc:
        sys.exit(f"\n[-] {exc}")
    print()
    with open(args.out, "w") as fh:
        json.dump(capture, fh, indent=2)
    meta = capture["capture_meta"]
    print(f"[+] {meta['packet_count']} packets, {meta['flow_count']} flows, "
          f"{meta['connection_count']} PID-attributed connections -> {args.out}")

    findings = analyze_capture(capture)
    if args.findings_out:
        with open(args.findings_out, "w") as fh:
            json.dump({"network_findings": findings}, fh, indent=2)
        print(f"[+] Wrote {len(findings)} network findings to {args.findings_out}")
    for f in findings[:5]:
        print(f"    PID {f['pid']} ({f['process']}) -> {f['foreign_ip']}:"
              f"{f['foreign_port']} score={f['score']} {f['flags']}")


if __name__ == "__main__":
    main()
