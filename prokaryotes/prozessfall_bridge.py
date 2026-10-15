
#!/usr/bin/env python3
"""
Prozessfall — Python-Rust FFI Bridge
JSON communication with the Prokaryotes Rust binary via subprocess.
"""
 
import json
import subprocess
import threading
from pathlib import Path
 
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prozessfall_config import PROZESSFALL_DB, PROKARYOTES_BIN
 
class ProkaryotesBridge:
    """
    Subprocess bridge to the Prokaryotes Rust binary.
    Thread-safe, persistent process — does not restart on each call.
    """
 
    def __init__(self, bin_path=PROKARYOTES_BIN):
        self.bin_path = str(bin_path)
        self._proc = None
        self._lock = threading.Lock()
        self._start()
 
    def _start(self):
        self._proc = subprocess.Popen(
            [self.bin_path, "--json"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line buffered
        )
 
    def _send(self, payload: dict) -> dict:
        """Send JSON, receive JSON."""
        with self._lock:
            line = json.dumps(payload) + "\n"
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
            response = self._proc.stdout.readline()
            return json.loads(response.strip())
 
    def absorb(self, delta_id: str, outcome: int) -> dict:
        """
        Send a binary decision.
        outcome: 0 = noise, 1 = opportunity
        Returns: {status, coherence, epsilon, invariants}
        """
        return self._send({"delta_id": delta_id, "outcome": outcome})
 
    def status(self) -> dict:
        """Get the current Prokaryotes state."""
        return self._send({"cmd": "status"})
 
    def close(self):
        """Close the bridge."""
        try:
            self._send({"cmd": "quit"})
        except Exception:
            pass
        self._proc.terminate()
 
    def __enter__(self):
        return self
 
    def __exit__(self, *args):
        self.close()
 
 
def bridge_from_structural(conn, bridge, subsystem_filter=None, limit=20):
    """
    Feed structural correlation results to Prokaryotes.
    High delta = opportunity (1), low delta = noise (0).
    Threshold: delta > 1.0 → opportunity
    """
    query = """
        SELECT cve_id, cvss_score, cwe_ids, description
        FROM cve_raw
        WHERE cvss_score IS NOT NULL
    """
    params = []
    if subsystem_filter:
        query += " AND description LIKE ?"
        params.append(f"%{subsystem_filter}%")
    query += " ORDER BY cvss_score DESC LIMIT ?"
    params.append(limit)
 
    rows = conn.execute(query, params).fetchall()
    results = []
 
    for row in rows:
        cve_id, cvss_score, cwe_ids, desc = row
        import json as _json
        cwes = _json.loads(cwe_ids) if cwe_ids else []
 
        # Compute delta — simple version from structural correlation
        cwe_weights = {
            "CWE-416": 1.0, "CWE-787": 0.9, "CWE-362": 0.85,
            "CWE-125": 0.8, "CWE-190": 0.75, "CWE-476": 0.6,
            "CWE-401": 0.4,
        }
        cwe_weight = max(
            (cwe_weights.get(c, 0.3) for c in cwes),
            default=0.3
        )
        delta = (cvss_score / 10.0) * cwe_weight
 
        # Threshold: delta > 0.8 → opportunity
        outcome = 1 if delta > 0.8 else 0
 
        response = bridge.absorb(cve_id, outcome)
        results.append({
            "cve_id":   cve_id,
            "delta":    round(delta, 4),
            "outcome":  outcome,
            "response": response,
        })
 
    return results
 
 
def bridge_from_msrc(conn, bridge, limit=20):
    """
    Feed MSRC Exploitation Detected CVEs to Prokaryotes.
    Exploitation Detected → opportunity (1)
    """
    rows = conn.execute("""
        SELECT cve_id, cvss_score, product_tag, exploitability
        FROM msrc_advisory
        WHERE cvss_score IS NOT NULL
        ORDER BY
            CASE exploitability
                WHEN 'detected'     THEN 1
                WHEN 'more_likely'  THEN 2
                WHEN 'less_likely'  THEN 3
                ELSE 4
            END,
            cvss_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
 
    results = []
    for row in rows:
        cve_id, cvss_score, product_tag, exploitability = row
 
        outcome = 1 if exploitability == "detected" else (
            1 if (cvss_score or 0) >= 9.0 else 0
        )
 
        delta_id = f"msrc:{cve_id}"
        response = bridge.absorb(delta_id, outcome)
        results.append({
            "cve_id":        cve_id,
            "product_tag":   product_tag,
            "exploitability": exploitability,
            "outcome":       outcome,
            "response":      response,
        })
 
    return results
 
 
def print_bridge_results(results, source=""):
    print(f"\n--- Bridge Results ({source}) ---")
    for r in results:
        resp = r.get("response", {})
        marker = "⚡" if r["outcome"] == 1 else "  "
        print(
            f"{marker} {r.get('cve_id', '')} "
            f"| coherence={resp.get('coherence', 0):.4f} "
            f"| epsilon={resp.get('epsilon', 0):.4f} "
            f"| invariants={resp.get('invariants', 0)}"
        )
 
 
if __name__ == "__main__":
    import sqlite3
 
    conn = sqlite3.connect(PROZESSFALL_DB)
 
    print("[*] Prokaryotes bridge starting...")
 
    with ProkaryotesBridge() as bridge:
        # Current state
        status = bridge.status()
        print(f"[*] Current state: {status}")
 
        # NVD ksmbd CVEs → bridge
        print("\n[*] feeding ksmbd CVEs...")
        results = bridge_from_structural(conn, bridge, subsystem_filter="ksmbd", limit=10)
        print_bridge_results(results, source="NVD/ksmbd")
 
        # MSRC Hyper-V CVEs → bridge
        print("\n[*] feeding MSRC Hyper-V CVEs...")
        hyper_v_rows = conn.execute("""
            SELECT cve_id, cvss_score, product_tag, exploitability
            FROM msrc_advisory
            WHERE product_tag LIKE '%Hyper-V%'
            ORDER BY cvss_score DESC
        """).fetchall()
 
        for row in hyper_v_rows:
            cve_id, cvss_score, product_tag, exploitability = row
            outcome = 1 if (cvss_score or 0) >= 9.0 else 0
            resp = bridge.absorb(f"msrc:{cve_id}", outcome)
            marker = "⚡" if outcome == 1 else "  "
            print(
                f"{marker} {cve_id} | {product_tag} | CVSS:{cvss_score} "
                f"| coherence={resp.get('coherence', 0):.4f}"
            )
 
        # Final state
        final = bridge.status()
        print(f"\n[*] Final state: {final}")
 
    conn.close()
    print("\n[*] Bridge closed.")
