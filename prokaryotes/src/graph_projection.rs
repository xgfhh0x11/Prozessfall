// SQLite → ProzessGraph projection (RELATIONAL mode).
//
// **Old hub-spoke mode (removed):** Each CVE was connected to a CweCluster/MsrcProduct
// hub → each cluster a star, and many clusters overlapping became a blob.
//
// **New relational mode:** Only CVE nodes. Between pairs of CVEs sharing the same CWE or
// MSRC product, a direct edge. The edge label carries the connection reason (cwe/product).
// Directed: high CVSS → low CVSS (the "exploits" / "leads to" feel from BloodHound).
//
// **Explosion control:** Pairwise among top-K (CVSS desc) members within each cluster.
// The CVSS < pairwise_min_cvss filter is applied first. This keeps edge count reasonable
// (~5-15k edges over 8000 CVEs, comparable to hub-spoke's 11k but the structure is
// completely different — the information is a network, not a star).
//
// Not included (Phase 2.5+):
//   - cve_embeddings → SemanticSimilar (BLOB format + cosine sim)
//   - Subsystem / SyntacticInvariant (come from runtime signals, not from ingestion)

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

use crate::graph::{GraphEdge, GraphNode, ProzessGraph};

/// Minimum CVSS for a pairwise edge — CVEs below this are ignored in edge generation.
/// The frontend applies its own filter on top (default 9.0); but the backend cap pre-trims.
const PAIRWISE_MIN_CVSS: f64 = 7.0;

/// Top-K members included in pairwise edge generation for each cluster (CWE or product).
/// 15 → 105 edges/cluster upper bound. 375 CWE × 105 = ~40k absolute worst case, in reality
/// much less because most clusters have <15 high-CVSS members.
const PAIRWISE_TOP_K: usize = 15;

struct CveInfo {
    id: String,
    cvss: f64,
    source: String,
    cwes: Vec<String>,
    msrc_product: Option<String>,
}

pub fn project_from_db(db_path: &Path) -> Result<ProzessGraph, String> {
    let started = Instant::now();
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open db ({}): {}", db_path.display(), e))?;

    let mut graph = ProzessGraph::new();
    let mut cve_map: HashMap<String, CveInfo> = HashMap::new();

    // ── 1. cve_raw → CveInfo (id, cvss, source, cwes) ─────────────────
    {
        let mut stmt = conn
            .prepare("SELECT cve_id, cvss_score, cwe_ids, source FROM cve_raw")
            .map_err(|e| format!("prepare cve_raw: {}", e))?;
        let rows = stmt
            .query_map([], |row| {
                let cve_id: String = row.get(0)?;
                let cvss: Option<f64> = row.get(1)?;
                let cwe_ids: Option<String> = row.get(2)?;
                let source: Option<String> = row.get(3)?;
                Ok((cve_id, cvss, cwe_ids, source))
            })
            .map_err(|e| format!("query cve_raw: {}", e))?;

        for row in rows {
            let (cve_id, cvss, cwe_ids_json, source) = row.map_err(|e| e.to_string())?;
            let cwes: Vec<String> = cwe_ids_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            cve_map.insert(
                cve_id.clone(),
                CveInfo {
                    id: cve_id,
                    cvss: cvss.unwrap_or(0.0),
                    source: source.unwrap_or_else(|| "NVD".to_string()),
                    cwes,
                    msrc_product: None,
                },
            );
        }
    }

    // ── 2. msrc_advisory → merge product_tag into CveInfo ─────────────
    {
        let mut stmt = conn
            .prepare(
                "SELECT cve_id, cvss_score, product_tag FROM msrc_advisory \
                 WHERE cve_id IS NOT NULL",
            )
            .map_err(|e| format!("prepare msrc_advisory: {}", e))?;
        let rows = stmt
            .query_map([], |row| {
                let cve_id: String = row.get(0)?;
                let cvss: Option<f64> = row.get(1)?;
                let product_tag: Option<String> = row.get(2)?;
                Ok((cve_id, cvss, product_tag))
            })
            .map_err(|e| format!("query msrc_advisory: {}", e))?;

        for row in rows {
            let (cve_id, cvss, product_tag) = row.map_err(|e| e.to_string())?;
            let entry = cve_map.entry(cve_id.clone()).or_insert_with(|| CveInfo {
                id: cve_id,
                cvss: cvss.unwrap_or(0.0),
                source: "MSRC".to_string(),
                cwes: Vec::new(),
                msrc_product: None,
            });
            if entry.msrc_product.is_none() {
                entry.msrc_product = product_tag;
            }
        }
    }

    let cve_count = cve_map.len();

    // ── 3. Add all CVE nodes ──────────────────────────────────
    for info in cve_map.values() {
        graph.upsert_node(GraphNode::Cve {
            id: info.id.clone(),
            cvss: Some(info.cvss),
            source: info.source.clone(),
        });
    }

    // ── 4. CWE inverted index → top-K pairwise edges ──────────────────
    let mut by_cwe: HashMap<String, Vec<&CveInfo>> = HashMap::new();
    for info in cve_map.values() {
        if info.cvss < PAIRWISE_MIN_CVSS {
            continue;
        }
        for cwe in &info.cwes {
            by_cwe.entry(cwe.clone()).or_default().push(info);
        }
    }

    let mut shares_cwe_edges = 0;
    for (cwe, members) in by_cwe.iter_mut() {
        members.sort_by(|a, b| b.cvss.partial_cmp(&a.cvss).unwrap_or(Ordering::Equal));
        let top = &members[..members.len().min(PAIRWISE_TOP_K)];
        for i in 0..top.len() {
            for j in (i + 1)..top.len() {
                // Direction: high CVSS → low (sort desc, i<j → top[i] >= top[j])
                if graph
                    .add_edge(
                        &top[i].id,
                        &top[j].id,
                        GraphEdge::SharesCwe { cwe: cwe.clone() },
                    )
                    .is_some()
                {
                    shares_cwe_edges += 1;
                }
            }
        }
    }

    // ── 5. MSRC product inverted index → top-K pairwise edges ─────────
    let mut by_product: HashMap<String, Vec<&CveInfo>> = HashMap::new();
    for info in cve_map.values() {
        if info.cvss < PAIRWISE_MIN_CVSS {
            continue;
        }
        if let Some(product) = &info.msrc_product {
            by_product.entry(product.clone()).or_default().push(info);
        }
    }

    let mut shares_product_edges = 0;
    for (product, members) in by_product.iter_mut() {
        members.sort_by(|a, b| b.cvss.partial_cmp(&a.cvss).unwrap_or(Ordering::Equal));
        let top = &members[..members.len().min(PAIRWISE_TOP_K)];
        for i in 0..top.len() {
            for j in (i + 1)..top.len() {
                if graph
                    .add_edge(
                        &top[i].id,
                        &top[j].id,
                        GraphEdge::SharesProduct {
                            product: product.clone(),
                        },
                    )
                    .is_some()
                {
                    shares_product_edges += 1;
                }
            }
        }
    }

    eprintln!(
        "[graph-projection] relational | {} CVEs | {} CWE clusters, {} products (after CVSS>={} filter) | \
         shares_cwe={} shares_product={} | total nodes={} edges={} | {}ms",
        cve_count,
        by_cwe.len(),
        by_product.len(),
        PAIRWISE_MIN_CVSS,
        shares_cwe_edges,
        shares_product_edges,
        graph.node_count(),
        graph.edge_count(),
        started.elapsed().as_millis(),
    );

    Ok(graph)
}
