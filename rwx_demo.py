#!/usr/bin/env python3
"""
rwx_demo.py — BENIGN test harness for the memory-forensics detectors.
=====================================================================
Purpose: produce the exact artifact your detectors look for, with ZERO
malware, so you can demo malfind / thread_binding.py on a REAL capture.

WHAT IT DOES:
  Allocates PAGE_EXECUTE_READWRITE memory *inside its own process*, writes
  a tiny CPU-spin stub into it, and starts a thread there. That thread's
  start address is therefore in PRIVATE, EXECUTABLE, NON-IMAGE-BACKED
  memory AND it burns CPU -> exactly the (unbacked + high-CPU) signature
  that windows.malfind and thread_binding.py flag.

WHAT IT IS **NOT**:
  No injection into any other process. No network. No file I/O. No
  persistence. No payload. The stub does nothing but increment a CPU
  register in a loop. This is a detection-test fixture, not malware, and
  it only affects its own process.

PLATFORM: Windows only (uses kernel32). NO VM REQUIRED — it is harmless.
NOTE: Windows Defender may warn about the RWX+thread pattern (the same
reason malfind flags it). If so, allow it / add a temporary exclusion;
it is benign. Running in a VM is optional, only to avoid that friction.

Usage (run as a normal user):
    python rwx_demo.py            # spins for 60s
    python rwx_demo.py 120        # spins for 120s
While it runs, capture RAM with WinPmem, then analyse memdump.raw with
thread_binding.py / heuristic_analyzer.py.
"""

import ctypes
import sys
import time
from ctypes import wintypes


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 60

    k = ctypes.windll.kernel32  # Windows only

    # Benign x86-64 stub:  loop: inc rax ; jmp loop
    #   48 FF C0   inc rax      (does nothing useful, just burns a cycle)
    #   EB FB      jmp -5       (back to inc -> infinite CPU-spin)
    STUB = bytes([0x48, 0xFF, 0xC0, 0xEB, 0xFB])

    MEM_COMMIT_RESERVE = 0x3000
    PAGE_EXECUTE_READWRITE = 0x40

    k.VirtualAlloc.restype = ctypes.c_void_p
    addr = k.VirtualAlloc(None, len(STUB), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        print("[rwx_demo] VirtualAlloc failed; nothing to do.")
        return
    ctypes.memmove(addr, STUB, len(STUB))

    k.CreateThread.restype = wintypes.HANDLE
    th = k.CreateThread(None, 0, ctypes.c_void_p(addr), None, 0, None)
    if not th:
        print("[rwx_demo] CreateThread failed.")
        return

    pid = k.GetCurrentProcessId()
    print(f"[rwx_demo] PID               = {pid}")
    print(f"[rwx_demo] RWX region        = 0x{addr:016x}   (unbacked, executable)")
    print(f"[rwx_demo] spinning thread running; this is the 'hashing' thread")
    print(f"[rwx_demo] capture window    = {seconds}s")
    print(f"[rwx_demo] >>> CAPTURE RAM NOW with WinPmem <<<   (Ctrl+C to stop early)")
    print(f"[rwx_demo] expect malfind to flag PID {pid}, and thread_binding.py")
    print(f"[rwx_demo] to label its thread HASHING_THREAD (unbacked + high CPU).")

    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    print("[rwx_demo] done — process exiting, thread stops.")


if __name__ == "__main__":
    main()
