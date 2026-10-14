#!/usr/bin/env python3
"""
evaluate.py
-----------
Measures DETECTION ACCURACY of the pipeline against a ground-truth label
set, and compares single-signal vs multi-signal detection to quantify
false-positive reduction (your "measured result").

You provide ground_truth.json:
    {
      "malicious_pids": [6278, 4053],     # PIDs that are TRULY malicious
      "benign_pids":    [8931, 1200, 1500, 1800]  # PIDs that are TRULY benign
    }
(For a sample dump, the lab walkthrough tells you the malicious PID; for
rwx_demo.py, you know its PID is the malicious one and everything else is
benign.)

HONESTY: on SYNTHETIC data the "ground truth" is whatever you planted, so
the numbers are circular and meaningless. This harness only produces a
real result on real/labeled data.

Usage:
    python evaluate.py --report final_report.json --truth ground_truth.json
"""

import argparse
import json


def flagged_pids_by_signal(report):
    """Return {signal_name: set(pids)} for each detection signal."""
    sig = {}
    sig["process (pslist/psscan)"] = {r["pid"] for r in report.get("process_findings", [])}
    sig["malfind (RWX region)"] = {r["pid"] for r in report.get("malfind_findings", [])}
    # strong mining traffic only (ignore weak score<80 like plain :443)
    sig["network (mining traffic)"] = {r["pid"] for r in report.get("network_findings", [])
                                       if r.get("score", 0) >= 80}
    # thread-level binding: only true HASHING_THREAD verdicts
    sig["thread-binding (HASHING_THREAD)"] = {
        r["pid"] for r in report.get("hashing_thread_findings", [])
        if r.get("verdict") == "HASHING_THREAD"}
    # MULTI-SIGNAL: flagged by >=2 independent categories
    counts = {}
    for name in ["process (pslist/psscan)", "malfind (RWX region)",
                 "network (mining traffic)", "thread-binding (HASHING_THREAD)"]:
        for pid in sig[name]:
            counts[pid] = counts.get(pid, 0) + 1
    sig["MULTI-SIGNAL (>=2 agree)"] = {pid for pid, c in counts.items() if c >= 2}
    return sig


def metrics(flagged, malicious, benign):
    malicious, benign, flagged = set(malicious), set(benign), set(flagged)
    population = malicious | benign
    flagged &= population  # only score PIDs we have a label for
    tp = len(flagged & malicious)
    fp = len(flagged & benign)
    fn = len(malicious - flagged)
    tn = len(benign - flagged)
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    acc = (tp + tn) / len(population) if population else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return dict(TP=tp, FP=fp, FN=fn, TN=tn,
                precision=prec, recall=rec, accuracy=acc, fpr=fpr)


def fmt(x):
    return "  n/a " if x is None else f"{x:5.2f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--truth", required=True)
    args = ap.parse_args()

    report = json.load(open(args.report))
    truth = json.load(open(args.truth))
    malicious = truth["malicious_pids"]
    benign = truth["benign_pids"]

    print(f"Ground truth: {len(malicious)} malicious, {len(benign)} benign\n")
    sigs = flagged_pids_by_signal(report)

    header = f"{'signal':<34} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  " \
             f"{'prec':>5} {'rec':>5} {'acc':>5} {'FPR':>5}"
    print(header)
    print("-" * len(header))
    for name, flagged in sigs.items():
        m = metrics(flagged, malicious, benign)
        print(f"{name:<34} {m['TP']:>3} {m['FP']:>3} {m['FN']:>3} {m['TN']:>3}  "
              f"{fmt(m['precision'])} {fmt(m['recall'])} {fmt(m['accuracy'])} {fmt(m['fpr'])}")

    print("\nRead it this way: compare a single signal's FP / FPR against the")
    print("MULTI-SIGNAL row. Fewer false positives there = your measured result.")


if __name__ == "__main__":
    main()
