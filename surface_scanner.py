#!/usr/bin/env python3
"""
Prozessfall — Surface Scanner

Prozessfall's actual defined function: "show the opportunity space."
Without locking scope, produces a ranked surface list across four axes over the whole DB:

    1. Density-driven    — CWE cluster + delta + dominant subsystem
    2. Severity outliers — distributional gap within the MSRC product family
    3. Semantic bridges  — cross-CWE high-similarity pairs
    4. Pressure spikes   — subsystem keyword density (description-based)

Usage:
    python3 surface_scanner.py                  # default top 10 per axis
    python3 surface_scanner.py --top 5
    python3 surface_scanner.py --output scan.md
"""

import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

from prozessfall_config import PROZESSFALL_DB as DB_PATH

CWE_WEIGHTS = {
    "CWE-416": 1.0, "CWE-787": 0.9, "CWE-362": 0.85,
    "CWE-125": 0.8, "CWE-190": 0.75, "CWE-476": 0.6,
    "CWE-401": 0.4,
}

# Curated subsystem keywords for pressure detection.
# Linux + Windows + cross-vendor surfaces.
# All matches are done case-insensitive.
SUBSYSTEM_KEYWORDS = [
    # Linux kernel subsystems
    "ksmbd", "io_uring", "netfilter", "nftables", "bpf", "ebpf",
    "vsock", "tcp", "udp", "ipv6", "ipv4", "kvm", "drm", "i915",
    "amdgpu", "btrfs", "ext4", "xfs", "f2fs", "nfs", "cifs",
    "usb", "bluetooth", "wifi", "mac80211", "cfg80211",
    "perf", "tracing", "ftrace", "uprobe", "kprobe", "ptrace",
    "namespaces", "cgroup", "seccomp", "apparmor", "selinux",
    "audit", "syscall", "scheduler", "memory management", "slab",
    "page cache", "vfs", "block layer", "scsi", "nvme",
    # Windows
    "hyper-v", "windows kernel", "ntdll", "win32k", "afd", "tcpip",
    "defender", "edge", "office", "sharepoint", "exchange",
    "patchguard", "secure boot", "bitlocker", "credential guard",
    "wdac", "vbs", "tpm", "clfs", "ntfs",
    # Hardware / firmware
    "uefi", "bios", "tpm", "spi", "rowhammer", "speculative",
    # Cross-vendor
    "openssl", "openssh", "samba", "qemu", "virtio",
]


# ──────────────────────────────────────────────────────────────────
# Density-driven CWE clusters
# ──────────────────────────────────────────────────────────────────

def scan_density(conn, top_n=10):
    """CWE-based cluster over the whole DB, ranked by structural delta."""
    rows = conn.execute("""
        SELECT cve_id, cvss_score, cwe_ids, description, affected
        FROM cve_raw
        WHERE cwe_ids IS NOT NULL AND cwe_ids != '[]'
    """).fetchall()

    clusters = defaultdict(list)
    for r in rows:
        try:
            cwes = json.loads(r[2])
        except Exception:
            continue
        for cwe in cwes:
            clusters[cwe].append({
                "cve_id": r[0],
                "cvss_score": r[1],
                "description": r[3] or "",
            })

    results = []
    for cwe, cves in clusters.items():
        scores = [c["cvss_score"] for c in cves if c["cvss_score"]]
        if not scores:
            continue
        avg = sum(scores) / len(scores)
        cwe_w = CWE_WEIGHTS.get(cwe, 0.5)
        # Density approx — n/3 cap, structural_corellation logic
        density = min(len(cves) / 3.0, 1.0)
        delta = round((avg / 10.0) * cwe_w * (1 + density), 4)

        # Dominant subsystem extraction from description keywords
        dominant = extract_dominant_subsystem(cves)

        results.append({
            "cwe": cwe,
            "count": len(cves),
            "avg_cvss": round(avg, 2),
            "delta": delta,
            "dominant_subsystem": dominant,
            "top_cves": [c["cve_id"] for c in
                         sorted(cves, key=lambda x: x["cvss_score"] or 0, reverse=True)[:3]],
        })

    results.sort(key=lambda x: x["delta"], reverse=True)
    return results[:top_n]


def _keyword_pattern(kw):
    """Word-boundary aware regex for subsystem keyword."""
    # Multi-word keywords (e.g., "windows kernel") word-boundary on both ends
    return re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)


# Pre-compile once
SUBSYSTEM_PATTERNS = [(kw, _keyword_pattern(kw)) for kw in SUBSYSTEM_KEYWORDS]


def extract_dominant_subsystem(cves):
    """Find the most frequent subsystem keyword in CVE descriptions (word-boundary)."""
    counts = defaultdict(int)
    for c in cves:
        desc = c["description"]
        for kw, pattern in SUBSYSTEM_PATTERNS:
            if pattern.search(desc):
                counts[kw] += 1
    if not counts:
        return None
    return max(counts.items(), key=lambda x: x[1])


# ──────────────────────────────────────────────────────────────────
# Severity outliers (MSRC)
# ──────────────────────────────────────────────────────────────────

def scan_outliers(conn, top_n=10):
    """
    MSRC product_tag based: singletons with a high distributional gap.
    Output: the gulf between the max CVSS within a product_tag and the rest.
    """
    rows = conn.execute("""
        SELECT cve_id, product_tag, cvss_score, exploitability, severity
        FROM msrc_advisory
        WHERE cvss_score IS NOT NULL AND product_tag IS NOT NULL
    """).fetchall()

    by_product = defaultdict(list)
    for r in rows:
        by_product[r[1]].append({
            "cve_id": r[0],
            "cvss_score": r[2],
            "exploitability": r[3],
            "severity": r[4],
        })

    results = []
    for product, cves in by_product.items():
        sorted_cves = sorted(cves, key=lambda x: x["cvss_score"], reverse=True)
        top = sorted_cves[0]
        max_cvss = top["cvss_score"]
        n_siblings = len(sorted_cves) - 1

        # Singleton product → no meaningful outlier signal (no sibling baseline).
        # The purpose of this category is "a single high score standing out within a small cluster" — Hyper-V style.
        # We don't eliminate the singleton entirely but keep outlier_score low; let those with siblings stand out.
        if n_siblings == 0:
            gap = 0.0
            outlier_score = max_cvss / 10.0 * 0.3  # singleton penalty
        else:
            second = sorted_cves[1]["cvss_score"]
            gap = max_cvss - second
            # Outlier score: gap × severity, meaning increases as sibling count grows
            # (a high score among 10 siblings is a stronger signal than among 1 sibling)
            sibling_weight = min(n_siblings / 3.0, 1.5)  # cap at 1.5x for 3+ siblings
            outlier_score = round(gap * (max_cvss / 10.0) * sibling_weight, 4)

        # Boost: exploitation detected = critical signal regardless of cluster shape
        if top["exploitability"] and "detected" in str(top["exploitability"]).lower():
            outlier_score += 1.0

        results.append({
            "cve_id": top["cve_id"],
            "product_tag": product,
            "cvss_score": max_cvss,
            "second_cvss": sorted_cves[1]["cvss_score"] if n_siblings else None,
            "gap": round(gap, 2),
            "siblings": n_siblings,
            "exploitability": top["exploitability"],
            "severity": top["severity"],
            "outlier_score": round(outlier_score, 4),
        })

    results.sort(key=lambda x: x["outlier_score"], reverse=True)
    return results[:top_n]


# ──────────────────────────────────────────────────────────────────
# Cross-CWE semantic bridges
# ──────────────────────────────────────────────────────────────────

def scan_bridges(conn, top_n=10, min_sim=0.80):
    """High-similarity cross-CWE pairs in the cve_embeddings table."""
    emb_rows = conn.execute(
        "SELECT cve_id, embedding FROM cve_embeddings"
    ).fetchall()
    if not emb_rows:
        return {"status": "empty", "data": []}

    emb_map = {r[0]: np.frombuffer(r[1], dtype=np.float32) for r in emb_rows}
    ids = list(emb_map.keys())

    # CWE lookup
    cwe_rows = conn.execute(
        f"SELECT cve_id, cwe_ids FROM cve_raw WHERE cve_id IN ({','.join('?'*len(ids))})",
        ids
    ).fetchall()
    cwe_map = {r[0]: (json.loads(r[1]) if r[1] else []) for r in cwe_rows}

    bridges = []
    n = len(ids)
    for i in range(n):
        ai = ids[i]
        a_emb = emb_map[ai]
        a_norm = np.linalg.norm(a_emb)
        a_cwes = set(cwe_map.get(ai, []))
        # Skip if A has no CWE — can't bridge cross-class without class on one side
        if not a_cwes:
            continue
        for j in range(i + 1, n):
            bj = ids[j]
            b_cwes = set(cwe_map.get(bj, []))
            # For the bridge to be meaningful: B must have a CWE, and it must differ from A's
            if not b_cwes:
                continue
            if a_cwes == b_cwes:
                continue
            if not a_cwes.isdisjoint(b_cwes):
                # Partial overlap — same class, skip
                continue
            b_emb = emb_map[bj]
            sim = float(np.dot(a_emb, b_emb) / (a_norm * np.linalg.norm(b_emb)))
            if sim >= min_sim:
                bridges.append({
                    "cve_a": ai,
                    "cve_b": bj,
                    "cwes_a": sorted(a_cwes),
                    "cwes_b": sorted(b_cwes),
                    "similarity": round(sim, 4),
                })

    bridges.sort(key=lambda x: x["similarity"], reverse=True)
    return {"status": "ok", "data": bridges[:top_n]}


# ──────────────────────────────────────────────────────────────────
# Pressure spikes (subsystem keyword density)
# ──────────────────────────────────────────────────────────────────

def scan_pressure(conn, top_n=10):
    """Subsystem keyword density in descriptions — word-boundary aware."""
    rows = conn.execute(
        "SELECT cve_id, description, cvss_score FROM cve_raw WHERE description IS NOT NULL"
    ).fetchall()

    counts = defaultdict(lambda: {"count": 0, "scores": []})
    for r in rows:
        desc = r[1]
        for kw, pattern in SUBSYSTEM_PATTERNS:
            if pattern.search(desc):
                counts[kw]["count"] += 1
                if r[2]:
                    counts[kw]["scores"].append(r[2])

    results = []
    for kw, data in counts.items():
        avg_cvss = round(sum(data["scores"]) / len(data["scores"]), 2) if data["scores"] else 0.0
        # Pressure score = count × avg severity (weighted)
        pressure_score = round(data["count"] * (avg_cvss / 10.0), 2)
        results.append({
            "subsystem": kw,
            "count": data["count"],
            "avg_cvss": avg_cvss,
            "pressure_score": pressure_score,
        })

    results.sort(key=lambda x: x["pressure_score"], reverse=True)
    return results[:top_n]


# ──────────────────────────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────────────────────────

def render_terminal(scan, top_n):
    out = []
    out.append("=" * 72)
    out.append(f"PROZESSFALL — SURFACE SCAN (top {top_n} per axis)")
    out.append("=" * 72)

    # 1. Density
    out.append("")
    out.append("┌─ 1. DENSITY-DRIVEN CWE CLUSTERS ─────────────────────────────────────┐")
    for r in scan["density"]:
        bar = "█" * min(int(r["delta"] * 15), 30)
        dom = ""
        if r["dominant_subsystem"]:
            dom = f"  [dominant: {r['dominant_subsystem'][0]} ×{r['dominant_subsystem'][1]}]"
        out.append(f"  {r['cwe']:<10}  delta={r['delta']:<7.4f}  count={r['count']:<4}  "
                   f"avg_cvss={r['avg_cvss']:<5}  {bar}{dom}")
        out.append(f"             top CVEs: {', '.join(r['top_cves'])}")
    out.append("└──────────────────────────────────────────────────────────────────────┘")

    # 2. Outliers
    out.append("")
    out.append("┌─ 2. SEVERITY OUTLIERS (MSRC) ────────────────────────────────────────┐")
    for r in scan["outliers"]:
        exploit_marker = "⚡" if r["exploitability"] and "detected" in str(r["exploitability"]).lower() else " "
        second = f"vs {r['second_cvss']}" if r["second_cvss"] else "singleton"
        out.append(f" {exploit_marker} {r['cve_id']:<18}  CVSS={r['cvss_score']:<4}  "
                   f"({second})  gap={r['gap']:<4}  score={r['outlier_score']:<6.4f}")
        out.append(f"     product: {r['product_tag']}  siblings={r['siblings']}  "
                   f"exploit={r['exploitability']}")
    out.append("└──────────────────────────────────────────────────────────────────────┘")

    # 3. Bridges
    out.append("")
    out.append("┌─ 3. CROSS-CWE SEMANTIC BRIDGES ──────────────────────────────────────┐")
    if scan["bridges"]["status"] == "empty":
        out.append("  [!] No embeddings in DB. Run: python3 semantic_corellation.py")
    elif not scan["bridges"]["data"]:
        out.append("  No cross-CWE pairs above similarity threshold.")
    else:
        for r in scan["bridges"]["data"]:
            out.append(f"  sim={r['similarity']:.4f}  {r['cve_a']:<18} ↔ {r['cve_b']:<18}")
            out.append(f"             {r['cwes_a']} ↔ {r['cwes_b']}")
    out.append("└──────────────────────────────────────────────────────────────────────┘")

    # 4. Pressure
    out.append("")
    out.append("┌─ 4. SUBSYSTEM PRESSURE SPIKES (description-based, current window) ───┐")
    for r in scan["pressure"]:
        bar = "█" * min(int(r["pressure_score"] / 2), 30)
        out.append(f"  {r['subsystem']:<22}  count={r['count']:<4}  "
                   f"avg_cvss={r['avg_cvss']:<5}  score={r['pressure_score']:<6.2f}  {bar}")
    out.append("└──────────────────────────────────────────────────────────────────────┘")

    out.append("")
    out.append("Drill-down:")
    out.append("  python3 generate_vault_draft.py --case CWE-XXX --subsystem <name>")
    out.append("  python3 generate_vault_draft.py --case CVE-YYYY-NNNNN")
    out.append("")

    return "\n".join(out)


def render_markdown(scan, top_n):
    out = []
    out.append(f"# Prozessfall — Surface Scan")
    out.append("")
    out.append(f"> Top {top_n} per axis. Output of `surface_scanner.py`.")
    out.append("")

    out.append("## 1. Density-Driven CWE Clusters")
    out.append("")
    out.append("| CWE | Delta | Count | Avg CVSS | Dominant Subsystem | Top CVEs |")
    out.append("|-----|-------|-------|----------|---------------------|----------|")
    for r in scan["density"]:
        dom = f"{r['dominant_subsystem'][0]} (×{r['dominant_subsystem'][1]})" if r['dominant_subsystem'] else "—"
        out.append(f"| {r['cwe']} | {r['delta']:.4f} | {r['count']} | {r['avg_cvss']} | {dom} | "
                   f"{', '.join(r['top_cves'])} |")

    out.append("")
    out.append("## 2. Severity Outliers (MSRC)")
    out.append("")
    out.append("| CVE | CVSS | vs Second | Gap | Product | Siblings | Exploit | Score |")
    out.append("|-----|------|-----------|-----|---------|----------|---------|-------|")
    for r in scan["outliers"]:
        second = str(r["second_cvss"]) if r["second_cvss"] else "—"
        out.append(f"| {r['cve_id']} | {r['cvss_score']} | {second} | {r['gap']} | "
                   f"{r['product_tag']} | {r['siblings']} | {r['exploitability']} | "
                   f"{r['outlier_score']:.4f} |")

    out.append("")
    out.append("## 3. Cross-CWE Semantic Bridges")
    out.append("")
    if scan["bridges"]["status"] == "empty":
        out.append("> No embeddings in DB. Run `python3 semantic_corellation.py` first.")
    elif not scan["bridges"]["data"]:
        out.append("> No cross-CWE pairs above similarity threshold.")
    else:
        out.append("| Similarity | CVE A | CVE B | CWE A | CWE B |")
        out.append("|------------|-------|-------|-------|-------|")
        for r in scan["bridges"]["data"]:
            out.append(f"| {r['similarity']:.4f} | {r['cve_a']} | {r['cve_b']} | "
                       f"{r['cwes_a']} | {r['cwes_b']} |")

    out.append("")
    out.append("## 4. Subsystem Pressure Spikes")
    out.append("")
    out.append("| Subsystem | Count | Avg CVSS | Pressure Score |")
    out.append("|-----------|-------|----------|----------------|")
    for r in scan["pressure"]:
        out.append(f"| {r['subsystem']} | {r['count']} | {r['avg_cvss']} | {r['pressure_score']} |")

    out.append("")
    out.append("## Drill-down")
    out.append("")
    out.append("```bash")
    out.append("python3 generate_vault_draft.py --case CWE-XXX --subsystem <name>")
    out.append("python3 generate_vault_draft.py --case CVE-YYYY-NNNNN")
    out.append("```")
    return "\n".join(out)


# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────

def run_scan(conn, top_n=10):
    return {
        "density":  scan_density(conn, top_n),
        "outliers": scan_outliers(conn, top_n),
        "bridges":  scan_bridges(conn, top_n),
        "pressure": scan_pressure(conn, top_n),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prozessfall — Surface Scanner")
    parser.add_argument("--top", type=int, default=10,
                        help="Top N per axis (default: 10)")
    parser.add_argument("--output", default=None,
                        help="Markdown output file (default: terminal pretty print)")
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--min-sim", type=float, default=0.80,
                        help="Minimum cosine similarity for bridges (default: 0.80)")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    try:
        scan = run_scan(conn, top_n=args.top)
    finally:
        conn.close()

    if args.output:
        Path(args.output).write_text(render_markdown(scan, args.top))
        print(f"[*] Markdown scan written to {args.output}", file=sys.stderr)
    else:
        print(render_terminal(scan, args.top))
