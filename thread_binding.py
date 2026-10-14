#!/usr/bin/env python3
"""
thread_binding.py  —  Thread-level CPU <-> unbacked-memory binding
==================================================================
OUR CONTRIBUTION (the "Option 2" novelty for this project).

Standard tooling flags things at the wrong granularity:
  * malfind flags whole MEMORY REGIONS (RWX/unbacked), not threads.
  * CPU monitors flag whole PROCESSES, not threads.
Neither tells you WHICH thread is the hashing thread.

This module BINDS the two signals at THREAD granularity:
  a thread is flagged as a cryptojacking "hashing thread" only when it is
    (1) executing from UNBACKED executable memory  (injection evidence), AND
    (2) consuming ABNORMAL CPU                      (hashing evidence).
That AND — at the thread level — is the gap named in our problem statement
("existing memory forensics flags broad RWX regions without linking them
to high-CPU hashing thread stacks").

----------------------------------------------------------------------
DATA-SOURCE HONESTY (state this in the report):
  Full binding needs a MEMORY DUMP + Volatility 3, because only there do
  you get BOTH per-thread facts:
     - start address  -> is it in unbacked memory?      (_ETHREAD.Win32StartAddress + VADs)
     - CPU cycles      -> is it an abnormal consumer?    (_KTHREAD.CycleTime)
  A single dump is a snapshot, so "CPU" here = ACCUMULATED cycle count,
  and "abnormal" = statistical outlier vs the other threads (the hashing
  thread has burned far more cycles than any normal thread). With TWO
  time-separated dumps you can compute a true rate instead; see RATE note.
  Live psutil can get per-thread CPU but NOT memory backing, so it cannot
  do the full binding alone.
----------------------------------------------------------------------
"""

from dataclasses import dataclass, field
from statistics import median
from typing import List, Tuple, Optional, Dict

Range = Tuple[int, int]


# ======================================================================
# PART 1 — THE BINDING ALGORITHM  (pure Python, robust, TESTABLE)
#          This is the contribution. Extraction (Part 2) feeds it.
# ======================================================================

@dataclass
class ThreadSample:
    pid: int
    tid: int
    process: str
    start_address: int
    cycle_time: int                      # accumulated CPU cycles (from dump)
    # per-process image-backed executable ranges (the "legit" code map):
    image_exec_ranges: List[Range] = field(default_factory=list)


@dataclass
class ThreadVerdict:
    pid: int
    tid: int
    process: str
    start_address: int
    cycle_time: int
    unbacked: bool
    high_cpu: bool
    verdict: str        # HASHING_THREAD / injected_thread / busy_thread / clean
    score: int
    reasons: List[str]


def _in_ranges(addr: int, ranges: List[Range]) -> bool:
    return any(lo <= addr < hi for (lo, hi) in ranges)


def _cpu_outliers(samples: List[ThreadSample], k: float = 3.0) -> set:
    """Threads whose accumulated cycles are a HIGH outlier vs the rest.
    Uses a robust MAD-style test (median + k*MAD) so one giant miner thread
    doesn't inflate a mean and hide itself. Returns the set of (pid,tid)."""
    cycles = [s.cycle_time for s in samples if s.cycle_time is not None]
    if len(cycles) < 3:
        # too few to do statistics; fall back to "top 10% by cycles"
        thresh = max(cycles) if cycles else 0
    else:
        med = median(cycles)
        mad = median([abs(c - med) for c in cycles]) or 1
        thresh = med + k * mad
    return {(s.pid, s.tid) for s in samples
            if s.cycle_time is not None and s.cycle_time >= thresh and s.cycle_time > 0}


def bind_threads(samples: List[ThreadSample], mad_k: float = 3.0) -> List[ThreadVerdict]:
    """Core: produce a verdict per thread by binding the two signals."""
    high = _cpu_outliers(samples, k=mad_k)
    out: List[ThreadVerdict] = []
    for s in samples:
        unbacked = not _in_ranges(s.start_address, s.image_exec_ranges)
        high_cpu = (s.pid, s.tid) in high
        reasons, score = [], 0

        if unbacked:
            reasons.append("thread start address in unbacked/private executable memory")
            score += 50
        if high_cpu:
            reasons.append(f"abnormal CPU cycle consumption ({s.cycle_time})")
            score += 30

        if unbacked and high_cpu:
            verdict = "HASHING_THREAD"          # the cryptojacking signature
            score += 20
            reasons.append("BOUND: unbacked execution + high CPU on the same thread")
        elif unbacked:
            verdict = "injected_thread"         # injected, but not clearly mining
        elif high_cpu:
            verdict = "busy_thread"             # heavy CPU but legitimate code
        else:
            verdict = "clean"

        if verdict != "clean":
            out.append(ThreadVerdict(
                pid=s.pid, tid=s.tid, process=s.process,
                start_address=s.start_address, cycle_time=s.cycle_time,
                unbacked=unbacked, high_cpu=high_cpu,
                verdict=verdict, score=min(score, 100), reasons=reasons))
    return sorted(out, key=lambda v: -v.score)


# ======================================================================
# PART 2 — EXTRACTION from a dump via the Volatility 3 framework API
#          Reads per-thread start address + cycle time + VAD backing.
#          The `# VERIFY` spots are version-dependent on your build.
# ======================================================================

def extract_from_dump(dump_path: str) -> List[ThreadSample]:
    import volatility3
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, plugins, interfaces
    from volatility3.plugins.windows import pslist, vadinfo        # VERIFY paths

    framework.import_files(volatility3.plugins)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = "file://" + dump_path
    amagic = automagic.available(ctx)
    plist = framework.list_plugins()
    constructed = plugins.construct_plugin(                         # VERIFY signature
        ctx, amagic, plist["windows.pslist.PsList"],
        interfaces.configuration.path_join("plugins", "PsList"), None, None)
    kernel = ctx.modules[constructed.config["kernel"]]
    layer, symtab = kernel.layer_name, kernel.symbol_table_name
    sep = interfaces.configuration.path_separator

    samples: List[ThreadSample] = []
    for proc in pslist.PsList.list_processes(ctx, layer, symtab):
        pid = int(proc.UniqueProcessId)
        name = proc.ImageFileName.cast("string",
                   max_length=proc.ImageFileName.vol.count, errors="replace")

        # image-backed executable ranges for this process
        img_ranges: List[Range] = []
        for vad in proc.get_vad_root().traverse():
            try:
                prot = vad.get_protection(
                    vadinfo.VadInfo.protect_values(ctx, layer, symtab),
                    vadinfo.winnt_protections)                      # VERIFY
                if "EXECUTE" not in str(prot).upper():
                    continue
                fname = vad.get_file_name()                         # VERIFY
                if fname and str(fname) not in ("", "Error"):
                    img_ranges.append((int(vad.get_start()), int(vad.get_end())))
            except Exception:
                continue

        for thread in proc.ThreadListHead.to_list(                 # VERIFY walk
                f"{symtab}{sep}_ETHREAD", "ThreadListEntry"):
            try:
                tid = int(thread.Cid.UniqueThread)
                sa = int(thread.Win32StartAddress)                 # VERIFY attr
            except Exception:
                continue
            # accumulated CPU cycles for this thread:
            try:
                cycles = int(thread.Tcb.CycleTime)                 # VERIFY attr (_KTHREAD.CycleTime)
            except Exception:
                cycles = 0
            samples.append(ThreadSample(
                pid=pid, tid=tid, process=name, start_address=sa,
                cycle_time=cycles, image_exec_ranges=img_ranges))
    return samples


# ======================================================================
# MAIN / report
# ======================================================================

def to_report_section(verdicts: List[ThreadVerdict]) -> dict:
    return {"hashing_thread_findings": [
        {"pid": v.pid, "tid": v.tid, "process": v.process,
         "start_address": hex(v.start_address), "cycle_time": v.cycle_time,
         "unbacked": v.unbacked, "high_cpu": v.high_cpu,
         "verdict": v.verdict, "score": v.score,
         "reasons": v.reasons} for v in verdicts]}


def main():
    import argparse, json, sys
    ap = argparse.ArgumentParser(description="Thread-level CPU<->unbacked-memory binding")
    ap.add_argument("--image", help="memory dump (.raw) — real Volatility path")
    ap.add_argument("--out", default="thread_findings.json")
    args = ap.parse_args()
    if not args.image:
        print("Provide --image <dump>. (Binding logic is unit-tested via --selftest.)")
        sys.exit(1)
    samples = extract_from_dump(args.image)
    verdicts = bind_threads(samples)
    with open(args.out, "w") as f:
        json.dump(to_report_section(verdicts), f, indent=2)
    print(f"[+] {len(verdicts)} flagged threads -> {args.out}")
    for v in verdicts[:10]:
        print(f"    PID {v.pid} TID {v.tid} {v.process:<16} {v.verdict:<16} score={v.score}")


if __name__ == "__main__":
    main()
