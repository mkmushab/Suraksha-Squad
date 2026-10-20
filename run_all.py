#!/usr/bin/env python3
"""Start the 5 live Suraksha Squad uAgents as separate processes (each gets its own Agentverse mailbox).

    python run_all.py

Processes started:
  1. suraksha_domain_forensics (:8002) — Domain, Page APK Trap, SSRF & Reputation uAgent
  2. suraksha_message_analyst  (:8004) — Coercion Lexicon, Phone, Email SPF/DKIM & Pattern uAgent
  3. suraksha_upi_verifier     (:8005) — NPCI UPI VPA, Collect Trap, IFSC & Modulo-36 GSTIN uAgent
  4. suraksha_action_agent     (:8012) — Epistemic Skeptic Cross-Check & 1930 Action Drafts uAgent
  5. suraksha_concierge        (:8001) — ASI:One Front Door Orchestrator (ACP v0.3.0 + Cards + Payment v0.1.0)

Each agent prints an Agent Inspector link on startup. Open each link and click 'Connect' -> 'Mailbox'
so Agentverse and ASI:One can reach your local agents.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

if os.name == "nt":
    os.system("")  # Enable ANSI colors in Windows PowerShell / CMD

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

ROOT = Path(__file__).resolve().parent
AGENTS = [
    ("domain", "agents_live.domain_agent"),
    ("message", "agents_live.message_agent"),
    ("upi", "agents_live.upi_agent"),
    ("action", "agents_live.action_agent"),
    ("concierge", "agents_live.concierge_agent"),
]
COLORS = {
    "domain": "\033[94m",
    "message": "\033[96m",
    "upi": "\033[95m",
    "action": "\033[93m",
    "concierge": "\033[92m",
}


def pump(name: str, proc: subprocess.Popen) -> None:
    for line in iter(proc.stdout.readline, ""):
        if "Ledger unavailable" in line:
            continue
        sys.stdout.write(f"{COLORS[name]}[{name:9}]\033[0m {line}")
        sys.stdout.flush()


def main() -> None:
    procs = []
    child_env = os.environ.copy()
    child_env["PYTHONUTF8"] = "1"
    child_env["PYTHONIOENCODING"] = "utf-8"
    for name, module in AGENTS:
        p = subprocess.Popen(
            [sys.executable, "-u", "-m", module],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=child_env,
        )
        threading.Thread(target=pump, args=(name, p), daemon=True).start()
        procs.append(p)

    def stop(*_):
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        stop()


if __name__ == "__main__":
    main()
