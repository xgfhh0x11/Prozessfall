#!/usr/bin/env python3
"""
Prozessfall — MSRC Advisory Fetcher
Fetches Microsoft Security Response Center bulletins, saves them to the DB.
Source: api.msrc.microsoft.com/cvrf/v3.0
"""
 
import json
import sqlite3
import requests
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
 
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prozessfall_config import PROZESSFALL_DB as DB_PATH
MSRC_UPDATES_API = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_CVRF_API    = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{bulletin_id}"
HEADERS = {"Accept": "application/json"}
 
def init_msrc_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS msrc_advisory (
            cve_id          TEXT NOT NULL,
            bulletin_id     TEXT NOT NULL,
            bulletin_date   TEXT,
            product_tag     TEXT,
            cvss_score      REAL,
            cvss_vector     TEXT,
            exploitability  TEXT,
            severity        TEXT,
            source          TEXT DEFAULT 'MSRC',
            fetched_at      TEXT,
            PRIMARY KEY (cve_id, bulletin_id)
        )
    """)
    conn.commit()
 
def get_recent_bulletins(months_back=3):
    """Fetch the bulletin IDs of the last N months."""
    resp = requests.get(MSRC_UPDATES_API, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
 
    cutoff = datetime.utcnow() - timedelta(days=months_back * 30)
    bulletins = []
 
    for entry in data.get("value", []):
        try:
            date = datetime.fromisoformat(
                entry["InitialReleaseDate"].replace("Z", "")
            )
            if date >= cutoff and "Security Updates" in entry.get("DocumentTitle", ""):
                bulletins.append({
                    "id":   entry["ID"],
                    "date": entry["InitialReleaseDate"],
                    "title": entry["DocumentTitle"],
                })
        except Exception:
            continue
 
    bulletins.sort(key=lambda x: x["date"], reverse=True)
    print(f"[*] {len(bulletins)} bulletins found (last {months_back} months)")
    return bulletins
 
def parse_exploitability(value):
    """
    Normalize the exploitability string.
    Threat Type 1 Description format:
    "Publicly Disclosed:Yes;Exploited:Yes;Latest Software Release:Exploitation Detected"
    """
    if not value:
        return None
 
    # Parse the semicolon-separated format
    if ";" in value:
        for part in value.split(";"):
            part = part.strip()
            if "Latest Software Release:" in part:
                val = part.split(":", 1)[1].strip()
                return _normalize_exploitability(val)
        return None
 
    return _normalize_exploitability(value.strip())
 
def _normalize_exploitability(val):
    mapping = {
        "Exploitation Detected":    "detected",
        "Exploitation More Likely": "more_likely",
        "Exploitation Less Likely": "less_likely",
        "Exploitation Unlikely":    "unlikely",
        "N/A":                      "na",
    }
    return mapping.get(val, val.lower().replace(" ", "_"))
 
def fetch_bulletin(bulletin_id):
    """Fetch the CVE list of a single bulletin."""
    url = MSRC_CVRF_API.format(bulletin_id=bulletin_id)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[!] {bulletin_id} fetch error: {e}")
        return None
 
def parse_bulletin(data, bulletin_id, bulletin_date):
    """Extract the CVE list from the bulletin JSON."""
    cves = []
    vulnerabilities = data.get("Vulnerability", [])
 
    for vuln in vulnerabilities:
        cve_id = vuln.get("CVE", "")
        if not cve_id:
            continue
 
        # CVSS score and vector — take the first set
        cvss_score  = None
        cvss_vector = None
        for score_set in vuln.get("CVSSScoreSets", []):
            base = score_set.get("BaseScore")
            vec  = score_set.get("Vector", "")
            if base is not None:
                try:
                    cvss_score  = float(base)
                    cvss_vector = vec
                    break
                except (ValueError, TypeError):
                    pass
 
        # Severity — Threat Type 3
        severity = None
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 3:
                desc = threat.get("Description", {})
                if isinstance(desc, dict) and desc.get("Value"):
                    severity = desc["Value"]
                    break
 
        # Exploitability — Threat Type 1
        # Format: "Publicly Disclosed:Yes;Exploited:Yes;Latest Software Release:Exploitation Detected"
        exploitability = None
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 1:
                desc = threat.get("Description", {})
                if isinstance(desc, dict):
                    exploitability = parse_exploitability(desc.get("Value", ""))
                break
 
        # Product tag — Notes Type 7 (vendor/product name)
        product_tag = None
        for note in vuln.get("Notes", []):
            if note.get("Type") == 7:
                title = note.get("Title", "")
                if title and title not in ("Mariner", "Linux", "Microsoft"):
                    product_tag = title
                    break
        # Fallback: take from the Type 7 title (vendor for Mariner/Linux)
        if not product_tag:
            for note in vuln.get("Notes", []):
                if note.get("Type") == 7:
                    product_tag = note.get("Title")
                    break
 
        cves.append({
            "cve_id":         cve_id,
            "bulletin_id":    bulletin_id,
            "bulletin_date":  bulletin_date,
            "product_tag":    product_tag,
            "cvss_score":     cvss_score,
            "cvss_vector":    cvss_vector,
            "exploitability": exploitability,
            "severity":       severity,
            "fetched_at":     datetime.utcnow().isoformat(),
        })
 
    return cves
 
def fetch_msrc(conn, months_back=3):
    """Main MSRC fetch pipeline."""
    bulletins = get_recent_bulletins(months_back)
    total = 0
 
    for b in bulletins:
        print(f"[*] {b['id']} — {b['title']}")
        data = fetch_bulletin(b["id"])
        if not data:
            continue
 
        cves = parse_bulletin(data, b["id"], b["date"])
 
        for cve in cves:
            conn.execute("""
                INSERT OR REPLACE INTO msrc_advisory
                (cve_id, bulletin_id, bulletin_date, product_tag,
                 cvss_score, cvss_vector, exploitability, severity, fetched_at)
                VALUES
                (:cve_id, :bulletin_id, :bulletin_date, :product_tag,
                 :cvss_score, :cvss_vector, :exploitability, :severity, :fetched_at)
            """, cve)
 
        conn.commit()
        total += len(cves)
        print(f"    → {len(cves)} CVE saved")
        time.sleep(0.5)
 
    return total
 
def query_summary(conn):
    total = conn.execute("SELECT COUNT(*) FROM msrc_advisory").fetchone()[0]
    critical = conn.execute(
        "SELECT COUNT(*) FROM msrc_advisory WHERE cvss_score >= 9.0"
    ).fetchone()[0]
    detected = conn.execute(
        "SELECT COUNT(*) FROM msrc_advisory WHERE exploitability = 'detected'"
    ).fetchone()[0]
    hyper_v = conn.execute(
        "SELECT COUNT(*) FROM msrc_advisory WHERE product_tag LIKE '%Hyper-V%'"
    ).fetchone()[0]
    kernel = conn.execute(
        "SELECT COUNT(*) FROM msrc_advisory WHERE product_tag LIKE '%Kernel%'"
    ).fetchone()[0]
 
    print(f"\n--- MSRC DB Summary ---")
    print(f"Total CVE       : {total}")
    print(f"Critical (>=9.0): {critical}")
    print(f"Exploitation Det: {detected}")
    print(f"Hyper-V         : {hyper_v}")
    print(f"Windows Kernel  : {kernel}")
 
    print(f"\nLast 5 Exploitation Detected:")
    rows = conn.execute("""
        SELECT cve_id, cvss_score, product_tag, bulletin_id
        FROM msrc_advisory
        WHERE exploitability = 'detected'
        ORDER BY bulletin_date DESC
        LIMIT 5
    """).fetchall()
    for r in rows:
        print(f"  {r[0]} | CVSS: {r[1]} | {r[2]} | {r[3]}")
 
    print(f"\nHyper-V CVEs:")
    rows = conn.execute("""
        SELECT cve_id, cvss_score, exploitability, bulletin_id
        FROM msrc_advisory
        WHERE product_tag LIKE '%Hyper-V%'
        ORDER BY cvss_score DESC
    """).fetchall()
    for r in rows:
        print(f"  {r[0]} | CVSS: {r[1]} | {r[2]} | {r[3]}")
 
if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    init_msrc_table(conn)
 
    # Clear old data
    conn.execute("DELETE FROM msrc_advisory")
    conn.commit()
 
    print("[*] MSRC fetch starting (last 3 months)...")
    total = fetch_msrc(conn, months_back=3)
    print(f"\n[*] Done. Total {total} CVE.")
    query_summary(conn)
 
    conn.close()
