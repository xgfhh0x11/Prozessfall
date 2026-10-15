#!/usr/bin/env python3
"""
MSRC sidecar — long-running stdio JSON-RPC wrapper around msrc_fetcher.

Same protocol as the NVD sidecar; the only differences are the fetcher API
(months_back vs days_back) and the signal query table (msrc_advisory).

Protocol:
  request:   {"cmd": "fetch_delta", "months_back": 1}
  response:  {"status": "ok", "fetched": N, "cves": [{cve_id, cvss_score, source}]}
  request:   {"cmd": "status"}
  request:   {"cmd": "quit"}

Each CVE in the signal list gets source="msrc_ingestion" added — the Rust helper
is generic and reads the signal source from the item, not the caller default.
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
sys.path.insert(0, str(HERE / "prokaryotes"))

from prozessfall_config import PROZESSFALL_DB
from msrc_fetcher import init_msrc_table, fetch_msrc


@contextlib.contextmanager
def stdout_to_stderr():
    old = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old


def cmd_fetch_delta(args):
    months_back = int(args.get("months_back", 1))
    conn = sqlite3.connect(PROZESSFALL_DB)
    init_msrc_table(conn)

    with stdout_to_stderr():
        count = fetch_msrc(conn, months_back=months_back)

    cutoff = (datetime.utcnow() - timedelta(days=months_back * 30)).isoformat()
    rows = conn.execute(
        """
        SELECT cve_id, cvss_score
        FROM msrc_advisory
        WHERE bulletin_date >= ? AND cvss_score IS NOT NULL
        ORDER BY cvss_score DESC
        LIMIT 20
        """,
        (cutoff,),
    ).fetchall()
    conn.close()

    return {
        "status": "ok",
        "fetched": count,
        "window_months": months_back,
        "cves": [
            {"cve_id": r[0], "cvss_score": r[1], "source": "msrc_ingestion"}
            for r in rows
        ],
    }


def cmd_status(args):
    conn = sqlite3.connect(PROZESSFALL_DB)
    init_msrc_table(conn)
    total = conn.execute("SELECT COUNT(*) FROM msrc_advisory").fetchone()[0]
    detected = conn.execute(
        "SELECT COUNT(*) FROM msrc_advisory WHERE exploitability = 'detected'"
    ).fetchone()[0]
    conn.close()
    return {
        "status": "ok",
        "total_cves": total,
        "exploitation_detected": detected,
    }


COMMANDS = {
    "fetch_delta": cmd_fetch_delta,
    "status": cmd_status,
}


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    write({"status": "ready", "sidecar": "msrc"})
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
