#!/usr/bin/env python3
"""
Prozessfall — Structural Correlation Engine
Clusters CVEs by CWE class, vendor, severity, and time proximity.
Produces a delta: points in the same cluster where a patch may be missing.
"""
 
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
 
from prozessfall_config import PROZESSFALL_DB as DB_PATH
 
def load_cves(conn, subsystem_filter=None):
    query = "SELECT cve_id, published, cvss_score, cwe_ids, description, affected FROM cve_raw"
    params = []
    if subsystem_filter:
        query += " WHERE description LIKE ?"
        params.append(f"%{subsystem_filter}%")
    rows = conn.execute(query, params).fetchall()
    cves = []
    for row in rows:
        cves.append({
            "cve_id":      row[0],
            "published":   row[1],
            "cvss_score":  row[2],
            "cwe_ids":     json.loads(row[3]) if row[3] else [],
            "description": row[4],
            "affected":    json.loads(row[5]) if row[5] else [],
        })
    return cves
 
def cluster_by_cwe(cves):
    """Cluster by CWE class."""
    clusters = defaultdict(list)
    for cve in cves:
        if cve["cwe_ids"]:
            for cwe in cve["cwe_ids"]:
                clusters[cwe].append(cve)
        else:
            clusters["UNCATEGORIZED"].append(cve)
    return dict(clusters)
 
def temporal_proximity(cves, window_days=7):
    """
    Group CVEs that appeared in the same time window.
    Appeared within the same week = probably the same patch cycle.
    """
    if not cves:
        return []
 
    sorted_cves = sorted(cves, key=lambda x: x["published"])
    groups = []
    current_group = [sorted_cves[0]]
 
    for cve in sorted_cves[1:]:
        try:
            t1 = datetime.fromisoformat(current_group[-1]["published"].replace("Z",""))
            t2 = datetime.fromisoformat(cve["published"].replace("Z",""))
            if abs((t2 - t1).days) <= window_days:
                current_group.append(cve)
            else:
                groups.append(current_group)
                current_group = [cve]
        except Exception:
            current_group.append(cve)
 
    groups.append(current_group)
    return groups
 
def compute_delta(cluster_name, cves):
    """
    Produce a structural delta.
    High severity + same CWE + temporal proximity = high delta.
    """
    if not cves:
        return 0.0
 
    scores = [c["cvss_score"] for c in cves if c["cvss_score"]]
    avg_score = sum(scores) / len(scores) if scores else 0.0
 
    # Temporal proximity: how many CVEs within the same week?
    groups = temporal_proximity(cves, window_days=7)
    max_group_size = max(len(g) for g in groups) if groups else 1
 
    # CWE criticality weight
    cwe_weights = {
        "CWE-416": 1.0,   # UAF
        "CWE-787": 0.9,   # OOB Write
        "CWE-125": 0.8,   # OOB Read
        "CWE-362": 0.85,  # Race Condition
        "CWE-190": 0.75,  # Integer Overflow
        "CWE-476": 0.6,   # NULL Deref
        "CWE-401": 0.4,   # Memory Leak
        "UNCATEGORIZED": 0.3,
    }
    cwe_weight = cwe_weights.get(cluster_name, 0.5)
 
    # Delta = avg_score * cwe_weight * temporal_density
    temporal_density = min(max_group_size / 3.0, 1.0)
    delta = (avg_score / 10.0) * cwe_weight * (1 + temporal_density)
 
    return round(delta, 4)
 
def structural_correlation(conn, subsystem_filter=None):
    """Main structural correlation pipeline."""
    cves = load_cves(conn, subsystem_filter)
    if not cves:
        print("[!] No CVE found.")
        return []
 
    clusters = cluster_by_cwe(cves)
    results = []
 
    for cwe, cluster_cves in sorted(clusters.items(),
                                     key=lambda x: len(x[1]), reverse=True):
        delta = compute_delta(cwe, cluster_cves)
        groups = temporal_proximity(cluster_cves, window_days=7)
        scores = [c["cvss_score"] for c in cluster_cves if c["cvss_score"]]
        avg_score = sum(scores) / len(scores) if scores else 0.0
 
        result = {
            "cwe":        cwe,
            "count":      len(cluster_cves),
            "avg_cvss":   round(avg_score, 2),
            "delta":      delta,
            "temporal_groups": len(groups),
            "max_group":  max(len(g) for g in groups) if groups else 0,
            "cves":       [c["cve_id"] for c in cluster_cves],
        }
        results.append(result)
 
    # Sort by delta — highest first
    results.sort(key=lambda x: x["delta"], reverse=True)
    return results
 
def print_report(results, subsystem=None):
    header = f"STRUCTURAL CORRELATION"
    if subsystem:
        header += f" — {subsystem.upper()}"
    print(f"\n{'='*60}")
    print(header)
    print(f"{'='*60}")
 
    for r in results:
        bar = "█" * int(r["delta"] * 20)
        print(f"\n[{r['cwe']}]")
        print(f"  Count:    {r['count']} CVE")
        print(f"  Avg CVSS: {r['avg_cvss']}")
        print(f"  Delta:    {r['delta']:.4f}  {bar}")
        print(f"  Temporal: {r['temporal_groups']} group(s), max {r['max_group']} in one window")
        print(f"  CVEs:     {', '.join(r['cves'][:5])}")
        if len(r['cves']) > 5:
            print(f"            ... +{len(r['cves'])-5} more")
 
    print(f"\n{'='*60}")
    print(f"Highest delta → variant hunting priority")
    if results:
        top = results[0]
        print(f"Target: {top['cwe']} ({top['count']} CVEs, delta={top['delta']})")
    print(f"{'='*60}\n")
 
if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
 
    # Run for ksmbd
    print("[*] Running structural correlation for ksmbd...")
    results = structural_correlation(conn, subsystem_filter="ksmbd")
    print_report(results, subsystem="ksmbd")
 
    # Also run for the whole Linux kernel
    print("[*] Running structural correlation for linux kernel...")
    results_all = structural_correlation(conn, subsystem_filter="linux kernel")
    print_report(results_all[:10], subsystem="linux kernel (top 10)")
 
    conn.close()