#!/usr/bin/env python3
"""
Prozessfall — NVD Feed Fetcher
First step: fetch the NVD CVE feed, save it to local SQLite.
"""
 
import json
import sqlite3
import requests
import time
from datetime import datetime, timedelta
from pathlib import Path
 
# --- Config ---
from prozessfall_config import PROZESSFALL_DB as DB_PATH
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
 
def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_raw (
            cve_id      TEXT PRIMARY KEY,
            published   TEXT,
            modified    TEXT,
            description TEXT,
            cvss_score  REAL,
            cvss_vector TEXT,
            cwe_ids     TEXT,
            affected    TEXT,
            source      TEXT DEFAULT 'NVD',
            fetched_at  TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fetch_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fetched_at  TEXT,
            count       INTEGER,
            status      TEXT
        )
    """)
    conn.commit()
 
def parse_cve(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
 
    # Description (English)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
 
    # CVSS score + vector
    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break
 
    # CWE IDs
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc_item in weakness.get("description", []):
            val = desc_item.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
 
    # Affected products (CPE)
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    affected.append(cpe_match.get("criteria", ""))
 
    return {
        "cve_id":     cve_id,
        "published":  cve.get("published", ""),
        "modified":   cve.get("lastModified", ""),
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids":    json.dumps(cwe_ids),
        "affected":   json.dumps(affected[:20]),  # first 20, storage optimization
        "fetched_at": datetime.utcnow().isoformat()
    }
 
def fetch_nvd(conn, days_back=30):
    """Fetch the CVEs of the last N days."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
 
    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
 
    start_index = 0
    total_fetched = 0
 
    print(f"[*] NVD fetch starting: {pub_start} → {pub_end}")
 
    while True:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate":   pub_end,
            "startIndex":   start_index,
            "resultsPerPage": RESULTS_PER_PAGE
        }
 
        try:
            resp = requests.get(NVD_API, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[!] Fetch error: {e}")
            break
 
        vulnerabilities = data.get("vulnerabilities", [])
        total_results   = data.get("totalResults", 0)
 
        if not vulnerabilities:
            break
 
        # Write to DB
        for item in vulnerabilities:
            row = parse_cve(item)
            conn.execute("""
                INSERT OR REPLACE INTO cve_raw
                (cve_id, published, modified, description,
                 cvss_score, cvss_vector, cwe_ids, affected, fetched_at)
                VALUES
                (:cve_id, :published, :modified, :description,
                 :cvss_score, :cvss_vector, :cwe_ids, :affected, :fetched_at)
            """, row)
 
        conn.commit()
        total_fetched += len(vulnerabilities)
        print(f"[+] {total_fetched}/{total_results} CVE saved")
 
        if start_index + RESULTS_PER_PAGE >= total_results:
            break
 
        start_index += RESULTS_PER_PAGE
        time.sleep(1)  # NVD rate limit: 1 req/sec (without API key)
 
    # Fetch log
    conn.execute(
        "INSERT INTO fetch_log (fetched_at, count, status) VALUES (?, ?, ?)",
        (datetime.utcnow().isoformat(), total_fetched, "ok")
    )
    conn.commit()
    print(f"[*] Done. Total {total_fetched} CVE.")
    return total_fetched
 
def query_summary(conn):
    """DB summary."""
    total = conn.execute("SELECT COUNT(*) FROM cve_raw").fetchone()[0]
    critical = conn.execute(
        "SELECT COUNT(*) FROM cve_raw WHERE cvss_score >= 9.0"
    ).fetchone()[0]
    high = conn.execute(
        "SELECT COUNT(*) FROM cve_raw WHERE cvss_score >= 7.0 AND cvss_score < 9.0"
    ).fetchone()[0]
    latest = conn.execute(
        "SELECT cve_id, cvss_score, published FROM cve_raw ORDER BY published DESC LIMIT 5"
    ).fetchall()
 
    print(f"\n--- DB Summary ---")
    print(f"Total CVE  : {total}")
    print(f"Critical   : {critical}")
    print(f"High       : {high}")
    print(f"\nLast 5 CVE:")
    for row in latest:
        print(f"  {row[0]} | CVSS: {row[1]} | {row[2][:10]}")
 
if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
 
    # Fetch the last 30 days
    fetch_nvd(conn, days_back=30)
    query_summary(conn)
 
    conn.close()