#!/usr/bin/env python3
"""
NVD sidecar — long-running stdio JSON-RPC wrapper around nvd_fetcher.

Tauri daemon spawns this at startup, communicates via stdin/stdout.
Each stdin line is a JSON command; each response is a JSON line to stdout.
Stderr is free — for diagnostic logging, the daemon does not parse it.

Protocol:
  request:   {"cmd": "fetch_delta", "days_back": 7}
  response:  {"status": "ok", "fetched": 42, "cves": [...]}
  request:   {"cmd": "status"}
  response:  {"status": "ok", "total_cves": 6336}
  request:   {"cmd": "quit"}
  response:  {"status": "bye"}  → process exits

Important: nvd_fetcher.fetch_nvd() writes to stdout with print() — to avoid
polluting the JSON-RPC, we redirect stdout to stderr.
"""

import contextlib
import json
import sqlite3
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from prozessfall_config import PROZESSFALL_DB
from nvd_fetcher import init_db, fetch_nvd


@contextlib.contextmanager
def stdout_to_stderr():
    """Redirect nvd_fetcher's print()s to stderr — stdout is reserved for JSON-RPC."""
    old = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old


def cmd_fetch_delta(args):
    days_back = int(args.get("days_back", 1))
    conn = sqlite3.connect(PROZESSFALL_DB)
    init_db(conn)

    with stdout_to_stderr():
        count = fetch_nvd(conn, days_back=days_back)

    # For signal generation, return the highest-CVSS CVEs within the window.
    # The full list can be 6000+ — let's not spam the bus, publish top-20.
    cutoff = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
    rows = conn.execute(
        """
        SELECT cve_id, cvss_score
        FROM cve_raw
        WHERE published >= ? AND cvss_score IS NOT NULL
        ORDER BY cvss_score DESC
        LIMIT 20
        """,
        (cutoff,),
    ).fetchall()
    conn.close()

    return {
        "status": "ok",
        "fetched": count,
        "window_days": days_back,
        "cves": [{"cve_id": r[0], "cvss_score": r[1]} for r in rows],
    }


def cmd_status(args):
    conn = sqlite3.connect(PROZESSFALL_DB)
    init_db(conn)  # idempotent CREATE IF NOT EXISTS — creates fetch_log if missing
    total = conn.execute("SELECT COUNT(*) FROM cve_raw").fetchone()[0]
    last_fetch = conn.execute(
        "SELECT fetched_at, count FROM fetch_log WHERE status='ok' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return {
        "status": "ok",
        "total_cves": total,
        "last_fetch_at": last_fetch[0] if last_fetch else None,
        "last_fetch_count": last_fetch[1] if last_fetch else None,
    }


COMMANDS = {
    "fetch_delta": cmd_fetch_delta,
    "status": cmd_status,
}


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    write({"status": "ready", "sidecar": "nvd"})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            write({"status": "error", "error": f"bad json: {e}"})
            continue

        cmd = req.get("cmd")
        if cmd == "quit":
            write({"status": "bye"})
            return

        handler = COMMANDS.get(cmd)
        if not handler:
            write({"status": "error", "error": f"unknown cmd: {cmd}"})
            continue

        try:
            write(handler(req))
        except Exception as e:
            write({
                "status": "error",
                "error": str(e),
                "traceback": traceback.format_exc(),
            })


if __name__ == "__main__":
    main()
