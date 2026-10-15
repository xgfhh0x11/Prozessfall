#!/usr/bin/env python3
"""
Prozessfall — Semantic Correlation Engine
Converts CVE descriptions to embeddings and computes similarity.
Catches patterns that structural correlation cannot see.
"""
 
import json
import sqlite3
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer
 
from prozessfall_config import PROZESSFALL_DB as DB_PATH
MODEL_NAME = "all-MiniLM-L6-v2"  # lightweight, fast, local
 
def load_cves(conn, subsystem_filter=None, limit=500):
    query = """
        SELECT cve_id, description, cvss_score, cwe_ids
        FROM cve_raw
        WHERE description IS NOT NULL
        AND LENGTH(description) > 100
    """
    params = []
    if subsystem_filter:
        query += " AND description LIKE ?"
        params.append(f"%{subsystem_filter}%")
    query += " LIMIT ?"
    params.append(limit)
    return conn.execute(query, params).fetchall()
 
def extract_core(description):
    """
    Extract the core bug pattern from the description.
    Remove boilerplate, keep the essence.
    """
    lines = description.strip().split('\n')
    # Remove the "In the Linux kernel..." header
    filtered = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("In the Linux kernel"):
            continue
        if line.startswith("This is the same bug"):
            continue
        filtered.append(line)
    return ' '.join(filtered[:10])  # first 10 lines are enough
 
def compute_embeddings(cves, model):
    """Convert CVE descriptions to embeddings."""
    texts = []
    ids = []
    for row in cves:
        cve_id, desc, score, cwe = row
        core = extract_core(desc)
        texts.append(core)
        ids.append(cve_id)
    print(f"[*] computing {len(texts)} CVE embeddings...")
    embeddings = model.encode(texts, show_progress_bar=True, batch_size=32)
    return ids, embeddings
 
def cosine_similarity(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
 
def find_semantic_clusters(ids, embeddings, threshold=0.75):
    """
    Find CVE pairs with similarity above the threshold.
    Catches cross-CWE patterns that structural correlation misses.
    """
    n = len(ids)
    clusters = []
 
    for i in range(n):
        for j in range(i + 1, n):
            sim = cosine_similarity(embeddings[i], embeddings[j])
            if sim >= threshold:
                clusters.append({
                    "cve_a": ids[i],
                    "cve_b": ids[j],
                    "similarity": round(float(sim), 4)
                })
 
    clusters.sort(key=lambda x: x["similarity"], reverse=True)
    return clusters
 
def semantic_delta(cve_id, ids, embeddings, all_cves, top_k=5):
    """
    Find the most similar CVEs for a single CVE.
    For variant hunting: "which one is most similar to this CVE?"
    """
    idx = ids.index(cve_id)
    target_emb = embeddings[idx]
 
    scores = []
    for i, (eid, emb) in enumerate(zip(ids, embeddings)):
        if eid == cve_id:
            continue
        sim = cosine_similarity(target_emb, emb)
        scores.append((eid, sim))
 
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]
 
def save_embeddings(conn, ids, embeddings):
    """Save embeddings to the DB — avoid recomputation."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_embeddings (
            cve_id TEXT PRIMARY KEY,
            embedding BLOB
        )
    """)
    for cve_id, emb in zip(ids, embeddings):
        conn.execute(
            "INSERT OR REPLACE INTO cve_embeddings (cve_id, embedding) VALUES (?, ?)",
            (cve_id, emb.tobytes())
        )
    conn.commit()
    print(f"[*] {len(ids)} embeddings saved to DB.")
 
def load_embeddings_from_db(conn):
    """Load previously computed embeddings."""
    rows = conn.execute(
        "SELECT cve_id, embedding FROM cve_embeddings"
    ).fetchall()
    if not rows:
        return [], []
    ids = [r[0] for r in rows]
    embeddings = [np.frombuffer(r[1], dtype=np.float32) for r in rows]
    return ids, embeddings
 
def print_clusters(clusters, conn, top_n=20):
    print(f"\n{'='*60}")
    print(f"SEMANTIC CORRELATION — TOP {top_n} SIMILAR PAIRS")
    print(f"{'='*60}")
 
    for c in clusters[:top_n]:
        # Fetch the CWEs
        rows = conn.execute(
            "SELECT cwe_ids, cvss_score FROM cve_raw WHERE cve_id IN (?, ?)",
            (c["cve_a"], c["cve_b"])
        ).fetchall()
        cwes = [json.loads(r[0]) if r[0] else [] for r in rows]
        scores = [r[1] for r in rows]
 
        same_cwe = cwes[0] == cwes[1] if len(cwes) == 2 else False
        marker = "  " if same_cwe else "⚡"  # different CWE but similar = interesting
 
        print(f"\n{marker} [{c['similarity']:.4f}] {c['cve_a']} ↔ {c['cve_b']}")
        print(f"   CWE: {cwes[0]} ↔ {cwes[1]}")
        print(f"   CVSS: {scores[0]} ↔ {scores[1]}")
 
    cross_cwe = [c for c in clusters[:top_n]
                 if conn.execute(
                     "SELECT cwe_ids FROM cve_raw WHERE cve_id=?",
                     (c["cve_a"],)).fetchone()[0] !=
                    conn.execute(
                     "SELECT cwe_ids FROM cve_raw WHERE cve_id=?",
                     (c["cve_b"],)).fetchone()[0]]
 
    print(f"\n{'='*60}")
    print(f"Cross-CWE semantic matches: {len(cross_cwe)}")
    print(f"(same semantic pattern, different bug class → variant candidate)")
    print(f"{'='*60}\n")
 
if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
 
    # Have the embeddings been computed before?
    existing_ids, existing_embeddings = load_embeddings_from_db(conn)
 
    if existing_ids:
        print(f"[*] {len(existing_ids)} embeddings loaded from DB.")
        ids, embeddings = existing_ids, existing_embeddings
    else:
        print("[*] Loading model...")
        model = SentenceTransformer(MODEL_NAME)
 
        # ksmbd + linux kernel CVEs
        cves = load_cves(conn, subsystem_filter="linux kernel", limit=500)
        print(f"[*] {len(cves)} CVE loaded.")
 
        ids, embeddings = compute_embeddings(cves, model)
        embeddings = np.array(embeddings)
 
        save_embeddings(conn, ids, embeddings)
 
    embeddings = np.array(embeddings)
 
    # Find the semantic clusters
    print("[*] Semantic clustering...")
    clusters = find_semantic_clusters(ids, embeddings, threshold=0.80)
    print(f"[*] {len(clusters)} similar pairs found (threshold=0.80)")
 
    print_clusters(clusters, conn, top_n=20)
 
    # variant hunting for ksmbd UAF CVEs
    ksmbd_uaf = ["CVE-2026-31444", "CVE-2026-31718", "CVE-2026-43376"]
    for target in ksmbd_uaf:
        if target in ids:
            print(f"\n--- Semantic neighbors of {target} ---")
            neighbors = semantic_delta(target, ids, embeddings, None, top_k=5)
            for n_id, sim in neighbors:
                cwe = conn.execute(
                    "SELECT cwe_ids FROM cve_raw WHERE cve_id=?", (n_id,)
                ).fetchone()
                cwe = json.loads(cwe[0]) if cwe and cwe[0] else []
                print(f"  {sim:.4f} → {n_id} {cwe}")
 
    conn.close()