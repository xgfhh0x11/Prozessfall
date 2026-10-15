#!/usr/bin/env python3
"""
Semantic similarity sidecar — computes cosine similarity from cve_embeddings BLOBs.

BLOB format: numpy float32 array, written with tobytes()/frombuffer() (sentence-transformers
all-MiniLM-L6-v2 → 384-dim). Pairwise similarity matrix product (N×384) @ (384×N).
Pairs above the threshold are returned — added to the graph as SemanticSimilar edges.

Commands:
  {"cmd": "compute", "threshold": 0.80}  → pairwise edges
  {"cmd": "status"}
  {"cmd": "quit"}
"""

import contextlib
import json
import sqlite3
import sys
import traceback
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from prozessfall_config import PROZESSFALL_DB


@contextlib.contextmanager
def stdout_to_stderr():
    old = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old


def cmd_compute(args):
    threshold = float(args.get("threshold", 0.80))

    conn = sqlite3.connect(PROZESSFALL_DB)
    try:
        rows = conn.execute(
            "SELECT cve_id, embedding FROM cve_embeddings"
        ).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        return {"status": "error", "error": f"cve_embeddings table missing: {e}"}
    finally:
        conn.close()

    if len(rows) < 2:
        return {
            "status": "ok",
            "embeddings_count": len(rows),
            "edges": [],
            "threshold": threshold,
        }

    with stdout_to_stderr():
        ids = [r[0] for r in rows]
        emb = np.array(
            [np.frombuffer(r[1], dtype=np.float32) for r in rows],
            dtype=np.float32,
        )
        # Row normalize → cosine = dot product
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        normalized = emb / norms
        sim = normalized @ normalized.T

        edges = []
        n = len(ids)
        for i in range(n):
            for j in range(i + 1, n):
                s = float(sim[i, j])
                if s >= threshold:
                    edges.append({"from": ids[i], "to": ids[j], "similarity": s})

        sys.stderr.write(
            f"[semantic-sidecar] {n} embeddings, {len(edges)} pairs ≥ {threshold}\n"
        )

    return {
        "status": "ok",
        "embeddings_count": n,
        "edges": edges,
        "threshold": threshold,
    }


def cmd_status(args):
    conn = sqlite3.connect(PROZESSFALL_DB)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM cve_embeddings"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        count = 0
    conn.close()
    return {"status": "ok", "sidecar": "semantic", "embeddings_count": count}


COMMANDS = {"compute": cmd_compute, "status": cmd_status}


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    write({"status": "ready", "sidecar": "semantic"})
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
