#!/usr/bin/env python3
"""
Prozessfall — Vault Entry §0 Draft Generator

Auto-generates the §0 Discovery Trace section of the vault_entry_format.md
spec from structural + semantic + msrc data.

Usage:
    # Cluster mode (CWE-based)
    python generate_vault_draft.py --case CWE-416 --subsystem ksmbd

    # Singleton mode (CVE-based, sibling set via MSRC product_tag)
    python generate_vault_draft.py --case CVE-2026-40402

    # Write to file
    python generate_vault_draft.py --case CWE-416 --subsystem ksmbd --output draft.md
"""

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

from prozessfall_config import PROZESSFALL_DB as DB_PATH

# CWE weights (same as structural_corellation, kept in a single place)
CWE_WEIGHTS = {
    "CWE-416": 1.0, "CWE-787": 0.9, "CWE-362": 0.85,
    "CWE-125": 0.8, "CWE-190": 0.75, "CWE-476": 0.6,
    "CWE-401": 0.4,
}

# Structural pattern → hypothesis category (for paragraph 2 hypotheses)
PATTERN_HYPOTHESES = {
    ("CWE-416", "CWE-667"): "lifecycle invariant violated under locking-cascade",
    ("CWE-416", "CWE-362"): "race condition cascading into use-after-free",
    ("CWE-787", "CWE-190"): "integer overflow producing OOB write",
    ("CWE-125", "CWE-190"): "integer overflow producing OOB read",
    ("CWE-416", "CWE-416"): "shared root cause across callers of same primitive",
}


# ──────────────────────────────────────────────────────────────────
# Data layer
# ──────────────────────────────────────────────────────────────────

def get_window_stats(conn):
    """Global statistics for the 30-day window (for paragraph 1)."""
    total = conn.execute("SELECT COUNT(*) FROM cve_raw").fetchone()[0]
    linux = conn.execute(
        "SELECT COUNT(*) FROM cve_raw WHERE description LIKE '%Linux kernel%'"
    ).fetchone()[0]

    msrc_total = conn.execute("SELECT COUNT(*) FROM msrc_advisory").fetchone()[0]

    # Date range
    dates = conn.execute(
        "SELECT MIN(published), MAX(published) FROM cve_raw"
    ).fetchone()

    return {
        "nvd_total": total,
        "linux_kernel": linux,
        "msrc_total": msrc_total,
        "earliest": dates[0],
        "latest": dates[1],
    }


def get_cluster_cves(conn, cwe, subsystem=None):
    """Fetch the CVEs in a specific CWE + subsystem cluster."""
    query = """
        SELECT cve_id, published, cvss_score, cwe_ids, description
        FROM cve_raw
        WHERE cwe_ids LIKE ?
    """
    params = [f"%{cwe}%"]
    if subsystem:
        query += " AND description LIKE ?"
        params.append(f"%{subsystem}%")
    query += " ORDER BY published DESC"

    rows = conn.execute(query, params).fetchall()
    cluster = []
    for r in rows:
        cwes = json.loads(r[3]) if r[3] else []
        if cwe in cwes:
            cluster.append({
                "cve_id": r[0],
                "published": r[1],
                "cvss_score": r[2],
                "cwe_ids": cwes,
                "description": r[4],
            })
    return cluster


def get_subsystem_count(conn, subsystem):
    """Total CVE count for a subsystem name (within the window)."""
    return conn.execute(
        "SELECT COUNT(*) FROM cve_raw WHERE description LIKE ?",
        (f"%{subsystem}%",)
    ).fetchone()[0]


def get_msrc_cve(conn, cve_id):
    """Singleton CVE information from the MSRC advisory side."""
    row = conn.execute("""
        SELECT cve_id, bulletin_id, bulletin_date, product_tag,
               cvss_score, cvss_vector, exploitability, severity
        FROM msrc_advisory
        WHERE cve_id = ?
        LIMIT 1
    """, (cve_id,)).fetchone()
    if not row:
        return None
    return {
        "cve_id": row[0],
        "bulletin_id": row[1],
        "bulletin_date": row[2],
        "product_tag": row[3],
        "cvss_score": row[4],
        "cvss_vector": row[5],
        "exploitability": row[6],
        "severity": row[7],
    }


def get_msrc_product_cluster(conn, product_tag, exclude_cve=None):
    """
    Other CVEs with the same product_tag (sibling cluster).
    Partial match — "Windows Hyper-V" + "Hyper-V Server" should be caught together.
    Anchor: the last word of product_tag (e.g. "Hyper-V", "Defender", "Kernel").
    """
    # Extract the anchor word — the last space-separated word
    anchor = product_tag.split()[-1] if product_tag else product_tag
    pattern = f"%{anchor}%"
    rows = conn.execute("""
        SELECT cve_id, cvss_score, exploitability, product_tag
        FROM msrc_advisory
        WHERE product_tag LIKE ?
    """, (pattern,)).fetchall()
    cluster = []
    for r in rows:
        if exclude_cve and r[0] == exclude_cve:
            continue
        cluster.append({
            "cve_id": r[0],
            "cvss_score": r[1],
            "exploitability": r[2],
            "product_tag": r[3],
        })
    return cluster


def get_msrc_exploited_set(conn):
    """CVEs with exploitation detected in this window."""
    rows = conn.execute("""
        SELECT cve_id, product_tag, cvss_score
        FROM msrc_advisory
        WHERE exploitability = 'detected' OR exploitability = 'Exploitation Detected'
    """).fetchall()
    return [{"cve_id": r[0], "product_tag": r[1], "cvss_score": r[2]} for r in rows]


def get_msrc_adjacent_pressure(conn, primary_product_tag, top_n=3):
    """The densest adjacent product clusters in this window (Windows Kernel etc.)."""
    rows = conn.execute("""
        SELECT product_tag, COUNT(*) as cnt
        FROM msrc_advisory
        WHERE product_tag IS NOT NULL AND product_tag != ?
        GROUP BY product_tag
        ORDER BY cnt DESC
        LIMIT ?
    """, (primary_product_tag, top_n)).fetchall()
    return [{"product_tag": r[0], "count": r[1]} for r in rows]


def get_semantic_neighbors(conn, cve_id, top_k=5, min_sim=0.75):
    """The N most similar CVEs for a given CVE (from the cve_embeddings table)."""
    embs = conn.execute(
        "SELECT cve_id, embedding FROM cve_embeddings"
    ).fetchall()
    if not embs:
        return []

    emb_map = {r[0]: np.frombuffer(r[1], dtype=np.float32) for r in embs}
    if cve_id not in emb_map:
        return []

    target = emb_map[cve_id]
    scores = []
    for other_id, other_emb in emb_map.items():
        if other_id == cve_id:
            continue
        # cosine similarity
        sim = float(np.dot(target, other_emb) /
                    (np.linalg.norm(target) * np.linalg.norm(other_emb)))
        if sim >= min_sim:
            scores.append((other_id, sim))
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]


def get_cluster_semantic_bridges(conn, cluster_cves, min_sim=0.80, top_k=5):
    """The strongest outward semantic bridges of the CVEs within the cluster."""
    cluster_ids = {c["cve_id"] for c in cluster_cves}
    bridges = []
    for c in cluster_cves[:10]:  # sample, don't do a full pass on very large clusters
        neighbors = get_semantic_neighbors(conn, c["cve_id"], top_k=top_k, min_sim=min_sim)
        for neighbor_id, sim in neighbors:
            if neighbor_id in cluster_ids:
                continue
            # The other CVE's CWE
            row = conn.execute(
                "SELECT cwe_ids FROM cve_raw WHERE cve_id=?", (neighbor_id,)
            ).fetchone()
            other_cwes = json.loads(row[0]) if row and row[0] else []
            cluster_cwes = set()
            for cc in cluster_cves:
                cluster_cwes.update(cc["cwe_ids"])
            cross_cwe = any(c not in cluster_cwes for c in other_cwes)
            bridges.append({
                "from_cve": c["cve_id"],
                "to_cve": neighbor_id,
                "similarity": round(sim, 4),
                "other_cwes": other_cwes,
                "cross_cwe": cross_cwe,
            })

    # Take the highest similarity first
    bridges.sort(key=lambda x: x["similarity"], reverse=True)
    return bridges[:5]


# ──────────────────────────────────────────────────────────────────
# Cluster mode (CWE entry signal — density)
# ──────────────────────────────────────────────────────────────────

def render_cluster_paragraph_1(window, cluster, cwe, subsystem, subsystem_total=None):
    """Paragraph 1 — Entry Signal (density)."""
    n = len(cluster)
    scores = [c["cvss_score"] for c in cluster if c["cvss_score"]]
    avg_cvss = round(sum(scores) / len(scores), 2) if scores else 0.0

    # Delta calculation (structural_corellation logic)
    cwe_w = CWE_WEIGHTS.get(cwe, 0.5)
    # Temporal density rough estimate: assume tight if cluster exists
    temporal_density = min(n / 3.0, 1.0)
    delta = round((avg_cvss / 10.0) * cwe_w * (1 + temporal_density), 4)

    return (
        f"The surface was entered through a density observation in {subsystem or 'the relevant kernel'} "
        f"subsystem code. Within a single NVD fetch window ({window['nvd_total']} CVE total"
        + (f", {window['linux_kernel']} Linux kernel-tagged" if window['linux_kernel'] else "")
        + f"), {subsystem or 'this subsystem'} alone accounted for "
        f"{subsystem_total if subsystem_total else '[TODO subsystem total]'} CVEs — and structural clustering "
        f"surfaced a tight {cwe} group of {n} report{'s' if n != 1 else ''} at average CVSS {avg_cvss}, "
        f"scoring a temporal density delta of {delta}. Density at this concentration on a single subsystem "
        f"rarely reflects {n} independent bugs; it more often signals a shared lifecycle invariant that broke "
        f"for multiple callers at once, or a refactor whose blast radius exceeded review coverage. Either "
        f"reading points to a deeper structural fault than any one CVE describes in isolation."
    )


def render_cluster_paragraph_2(bridges, cwe):
    """Paragraph 2 — Lateral Expansion (semantic cross-CWE)."""
    cross_cwe_bridges = [b for b in bridges if b["cross_cwe"]]

    if not cross_cwe_bridges:
        return (
            f"Lateral expansion did not surface a high-similarity cross-CWE bridge within the current "
            f"semantic window — the cluster's pattern remains internal to {cwe}. "
            f"[TODO: when semantic enrichment grows, check for adjacent CWE classes that may share the same "
            f"underlying primitive (e.g., locking, lifecycle, refcount)]"
        )

    top = cross_cwe_bridges[0]
    other_cwe = top["other_cwes"][0] if top["other_cwes"] else "[TODO]"
    # Look up known hypothesis
    pair = tuple(sorted([cwe, other_cwe]))
    hypothesis = PATTERN_HYPOTHESES.get(pair, "shared underlying primitive across two CWE labels")

    return (
        f"Semantic correlation widened the surface from {cwe} alone. A cross-CWE bridge to {other_cwe} "
        f"appeared at similarity {top['similarity']:.2f} (between {top['from_cve']} and {top['to_cve']}) — "
        f"high enough that the two clusters are not describing distinct phenomena but the same phenomenon "
        f"under two CWE labels. This collapse points to a {hypothesis}. "
        f"The hypothesis at this point became concrete: a single primitive in the subsystem's "
        f"[TODO: name the path — e.g., session teardown / connection close / handle release] "
        f"is releasing an object whose other holders still treat it as live."
    )


def render_cluster_paragraph_3(cwe, subsystem):
    """Paragraph 3 — Elimination & Narrowing (syntactic invariant stub)."""
    return (
        f"Elimination narrowed from there. "
        f"[TODO: auto-fill once the syntactic-invariant impl lands — manual for now:\n"
        f" - Which pattern class was eliminated for being incompatible with strict per-X ownership?\n"
        f" - Which {subsystem or 'subsystem'} paths were ruled out by single-owner discipline?\n"
        f" - Which narrow surface remained?]\n\n"
        f"The bug surface narrows to that {subsystem or 'subsystem'} path; the specific function and "
        f"the precise window where the invariant fails is the subject of §3."
    )


# ──────────────────────────────────────────────────────────────────
# Singleton mode (CVE severity outlier entry signal)
# ──────────────────────────────────────────────────────────────────

def render_singleton_paragraph_1(window, msrc_cve, sibling_cluster):
    """Paragraph 1 — Entry Signal (severity outlier)."""
    product = msrc_cve["product_tag"]
    target_score = msrc_cve["cvss_score"]
    sibling_scores = sorted(
        [s["cvss_score"] for s in sibling_cluster if s["cvss_score"]],
        reverse=True
    )
    sibling_min = sibling_scores[-1] if sibling_scores else 0
    sibling_max = sibling_scores[0] if sibling_scores else 0

    return (
        f"The surface was entered through a severity-outlier observation in the most recent MSRC bulletin "
        f"window. Across {window['msrc_total']} vulnerabilities, {product} was represented by "
        f"{len(sibling_cluster) + 1} CVEs — a small cluster, statistically uninteresting on its own. "
        f"The signal was distributional: "
        f"{len(sibling_cluster)} of the {len(sibling_cluster) + 1} sat between CVSS {sibling_min:.1f} and "
        f"{sibling_max:.1f}, while one — {msrc_cve['cve_id']} — stood alone at {target_score:.1f}. "
        f"A single ≥9.0 case in {product} is a different shape of signal than a density cluster. "
        f"It does not say 'an invariant broke for many callers'; it says 'one path crosses a trust boundary "
        f"that the others don't.' "
        f"[TODO: trust-boundary explanation for the specific {product} — guest-to-host? user-to-kernel? "
        f"network-to-host? — CVSS vector'den oku] "
        f"The entry was the gap between the outlier and its siblings, not the cluster itself."
    )


def render_singleton_paragraph_2(adjacent_pressure, product, sibling_count):
    """Paragraph 2 — Lateral Expansion (cross-surface adjacent)."""
    if not adjacent_pressure:
        return (
            f"Lateral expansion did not surface adjacent product pressure in the current window. "
            f"[TODO: this is rare — bulk MSRC data exists; if this message appears the fetcher is empty]"
        )

    top = adjacent_pressure[0]
    return (
        f"Lateral expansion had to look outside the {product} cluster, since {sibling_count} "
        f"cases cannot support intra-cluster semantic correlation. The dominant adjacent surface in the same "
        f"window was {top['product_tag']} with {top['count']} CVEs — "
        f"[TODO: explain this adjacent surface's structural relationship to {product} — host kernel? component "
        f"sharing? post-exploit pivot target?]. "
        f"The hypothesis that crystallized: this is not an internal {product} bug class (those tend to "
        f"score 7-8 with privilege-bounded impact); this is a boundary-crossing class whose post-exploitation "
        f"chains directly into the actively-pressured adjacent surface."
    )


def render_singleton_paragraph_3(msrc_cve, exploited_set):
    """Paragraph 3 — Elimination & Narrowing (syntactic invariant stub)."""
    is_exploited = any(e["cve_id"] == msrc_cve["cve_id"] for e in exploited_set)
    exploited_names = ", ".join(e["product_tag"] for e in exploited_set[:5])

    lines = []
    lines.append("Elimination narrowed from there. Available negations from current data:")
    if not is_exploited:
        lines.append(
            f"- *Not in exploitation-detected set* ({len(exploited_set)} entries this window: "
            f"{exploited_names}; {msrc_cve['product_tag']} absent). "
            f"This places the case in the **pre-exploit window** — researcher value highest before public "
            f"weaponization, drops afterward."
        )
    else:
        lines.append(
            "- This case IS in the exploitation-detected set — pre-exploit window argument does not apply; "
            "value shifts to defensive analysis / detection bypass coverage."
        )

    lines.append(
        f"- [TODO: second negation — e.g. 'not management plane' / 'not known-hardened path' — "
        f"{msrc_cve['product_tag']} architecture bilgisinden manuel]"
    )
    lines.append(
        f"- [TODO: third negation if needed — auto-fill once the syntactic-invariant impl lands]"
    )
    lines.append("")
    lines.append(
        "What remains is a narrow band: [TODO: properties of the remaining narrow surface]. "
        "The specific component and bug class is the subject of §1-§3."
    )

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# Top-level dispatcher
# ──────────────────────────────────────────────────────────────────

def generate_cluster_draft(conn, cwe, subsystem=None):
    """Cluster mode (CWE-based)."""
    window = get_window_stats(conn)
    cluster = get_cluster_cves(conn, cwe, subsystem)
    if not cluster:
        return f"# §0 Discovery Trace — ERROR\n\nNo CVEs found for {cwe} + {subsystem}\n"

    bridges = get_cluster_semantic_bridges(conn, cluster)
    subsystem_total = get_subsystem_count(conn, subsystem) if subsystem else None

    out = []
    out.append(f"# §0 Discovery Trace — {cwe}" + (f" / {subsystem}" if subsystem else ""))
    out.append("")
    out.append(f"> Auto-generated by generate_vault_draft.py from prozessfall.db state.")
    out.append(f"> Cluster: {len(cluster)} CVE, CWE={cwe}, subsystem={subsystem or 'any'}")
    out.append(f"> Window: NVD={window['nvd_total']} CVE, Linux kernel={window['linux_kernel']}")
    out.append("")
    out.append("## Paragraph 1 — Entry Signal")
    out.append("")
    out.append(render_cluster_paragraph_1(window, cluster, cwe, subsystem, subsystem_total))
    out.append("")
    out.append("## Paragraph 2 — Lateral Expansion")
    out.append("")
    out.append(render_cluster_paragraph_2(bridges, cwe))
    out.append("")
    out.append("## Paragraph 3 — Elimination & Narrowing")
    out.append("")
    out.append(render_cluster_paragraph_3(cwe, subsystem))
    out.append("")
    out.append("---")
    out.append("")
    out.append("## Raw material (for manual pass)")
    out.append("")
    out.append(f"**Cluster CVEs ({len(cluster)}):**")
    for c in cluster[:10]:
        out.append(f"- `{c['cve_id']}` CVSS={c['cvss_score']} published={c['published'][:10]}")
    if len(cluster) > 10:
        out.append(f"- ... +{len(cluster)-10} more")
    out.append("")
    if bridges:
        out.append(f"**Semantic bridges (top {len(bridges)}):**")
        for b in bridges:
            marker = "⚡" if b["cross_cwe"] else "  "
            out.append(
                f"- {marker} {b['from_cve']} ↔ {b['to_cve']} "
                f"sim={b['similarity']:.4f} other_cwes={b['other_cwes']}"
            )
    else:
        out.append("**Semantic bridges:** none above 0.80 threshold")
    return "\n".join(out)


def generate_singleton_draft(conn, cve_id):
    """Singleton mode (CVE-based, MSRC product_tag sibling cluster)."""
    msrc_cve = get_msrc_cve(conn, cve_id)
    if not msrc_cve:
        return f"# §0 Discovery Trace — ERROR\n\nCVE {cve_id} not found in MSRC table\n"

    product = msrc_cve["product_tag"]
    sibling_cluster = get_msrc_product_cluster(conn, product, exclude_cve=cve_id)
    adjacent_pressure = get_msrc_adjacent_pressure(conn, product, top_n=3)
    exploited_set = get_msrc_exploited_set(conn)
    window = get_window_stats(conn)

    out = []
    out.append(f"# §0 Discovery Trace — {cve_id} ({product})")
    out.append("")
    out.append(f"> Auto-generated by generate_vault_draft.py from prozessfall.db state.")
    out.append(f"> Singleton: CVSS={msrc_cve['cvss_score']}, "
               f"exploitability={msrc_cve['exploitability']}, severity={msrc_cve['severity']}")
    out.append(f"> Sibling cluster ({product}): {len(sibling_cluster) + 1} CVE")
    out.append("")
    out.append("## Paragraph 1 — Entry Signal")
    out.append("")
    out.append(render_singleton_paragraph_1(window, msrc_cve, sibling_cluster))
    out.append("")
    out.append("## Paragraph 2 — Lateral Expansion")
    out.append("")
    out.append(render_singleton_paragraph_2(adjacent_pressure, product, len(sibling_cluster) + 1))
    out.append("")
    out.append("## Paragraph 3 — Elimination & Narrowing")
    out.append("")
    out.append(render_singleton_paragraph_3(msrc_cve, exploited_set))
    out.append("")
    out.append("---")
    out.append("")
    out.append("## Raw material (for manual pass)")
    out.append("")
    out.append(f"**Target CVE:** {cve_id}")
    out.append(f"- CVSS: {msrc_cve['cvss_score']} ({msrc_cve['cvss_vector']})")
    out.append(f"- Bulletin: {msrc_cve['bulletin_id']} ({msrc_cve['bulletin_date']})")
    out.append(f"- Exploitability: {msrc_cve['exploitability']}")
    out.append("")
    if sibling_cluster:
        out.append(f"**Sibling cluster ({product}, {len(sibling_cluster)} sibling):**")
        for s in sorted(sibling_cluster, key=lambda x: x["cvss_score"] or 0, reverse=True):
            out.append(f"- `{s['cve_id']}` CVSS={s['cvss_score']} exploit={s['exploitability']}")
    out.append("")
    if adjacent_pressure:
        out.append(f"**Adjacent surface pressure (top 3 in same window):**")
        for a in adjacent_pressure:
            out.append(f"- {a['product_tag']}: {a['count']} CVE")
    out.append("")
    out.append(f"**Exploitation Detected this window ({len(exploited_set)}):**")
    for e in exploited_set:
        out.append(f"- `{e['cve_id']}` ({e['product_tag']}) CVSS={e['cvss_score']}")
    return "\n".join(out)


def generate_vault_draft(conn, case_id, subsystem=None, mode="auto"):
    """Top-level dispatcher."""
    if mode == "auto":
        if case_id.startswith("CWE-"):
            mode = "cluster"
        elif case_id.startswith("CVE-"):
            mode = "singleton"
        else:
            raise ValueError(f"Cannot infer mode from case_id={case_id}; "
                             f"use --mode cluster|singleton")

    if mode == "cluster":
        return generate_cluster_draft(conn, case_id, subsystem)
    elif mode == "singleton":
        return generate_singleton_draft(conn, case_id)
    else:
        raise ValueError(f"Unknown mode: {mode}")


# ──────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prozessfall — Vault Entry §0 Draft Generator")
    parser.add_argument("--case", required=True,
                        help="CWE-XXX for cluster mode, CVE-XXXX-NNNNN for singleton mode")
    parser.add_argument("--subsystem", default=None,
                        help="Subsystem filter for cluster mode (e.g. ksmbd)")
    parser.add_argument("--mode", default="auto",
                        choices=["auto", "cluster", "singleton"])
    parser.add_argument("--output", default=None,
                        help="Output file path (default: stdout)")
    parser.add_argument("--db", default=str(DB_PATH))
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    try:
        draft = generate_vault_draft(conn, args.case, args.subsystem, args.mode)
    finally:
        conn.close()

    if args.output:
        Path(args.output).write_text(draft)
        print(f"[*] Draft written to {args.output}", file=sys.stderr)
    else:
        print(draft)
