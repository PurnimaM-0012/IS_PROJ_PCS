# IS_PROJ_PCS — Cryptojacking Detection

Detects cryptojacking on a real Windows machine by combining **memory forensics** and
**network analysis**:

* **Memory** — a kernel-only live memory dump (Task Manager) is analysed with
  Volatility 3: hidden processes, executable+writable memory regions, and
  **thread binding** — a thread is flagged as a hashing thread only when it runs from
  unbacked memory *and* consumes abnormal CPU.
* **Network** — a live capture (tshark + per-process connection tracking) scores
  connections for mining-pool behaviour: pool ports/domains, long-lived, small steady
  packets.
* **Dashboard** — a Streamlit app to capture, analyse, visualise and measure detection
  accuracy (precision / recall / false-positive rate per technique).

On a real laptop with one planted miner-like process, RWX-region detection alone
raised 17 alarms (precision 0.06); thread binding raised exactly one (precision 1.00)
with no loss of recall.

## Quick start

```powershell
pip install -r requirements.txt          # plus Wireshark with Npcap for capture
streamlit run streamlit_app.py
```

Then, in the sidebar:

1. **Kernel memory dump** — follow the steps to create a Task Manager live kernel dump
   and click **Analyse dump**.
2. **Forensics report** — view findings and label the dump to see accuracy.
3. **Live network capture** — capture or upload network traffic.

## Documentation

See **[docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md)** for the architecture, every
component, the detection rules and scoring, how live capture and dump analysis work,
a step-by-step demo, how to interpret the results, privacy notes and troubleshooting.

## Privacy

Memory dumps, packet captures, capture JSON and analysis reports contain data from the
machine they were taken on. They are git-ignored and, by default, stored outside the
project in `C:\memdumps`. Delete dumps after analysis.
