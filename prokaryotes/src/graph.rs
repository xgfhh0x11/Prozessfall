// ProzessGraph — graph representation of the opportunity space.
//
// Thin wrapper over petgraph::DiGraph<GraphNode, GraphEdge>.
// Stable string ID ↔ NodeIndex mapping → callers work with string IDs,
// petgraph internal indices stay hidden.
//
// Phase 2.1: schema + basic API + unit tests. Data population in Phase 2.2
// (SQLite → graph projection). Incremental update in Phase 2.3 (bus → diff).
//
// BloodHound analogy:
//   - Node = Principal/Computer/Group  →  CveNode/CweClusterNode/MsrcProductNode/...
//   - Edge = ACL/membership            →  SemanticSimilar/StructuralCluster/...
//   - Shortest path to Domain Admin    →  Shortest path from CVE to high-coherence invariant

use std::collections::HashMap;

use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::LayerSignal;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphNode {
    Cve {
        id: String,
        cvss: Option<f64>,
        source: String,
    },
    CweCluster {
        id: String,
        cwe: String,
        member_count: usize,
    },
    MsrcProduct {
        id: String,
        product_tag: String,
        cve_count: usize,
    },
    Subsystem {
        id: String,
        name: String,
        hit_count: usize,
    },
    SyntacticInvariant {
        id: String,
        pattern: String,
        negated_class: String,
    },
}

impl GraphNode {
    pub fn id(&self) -> &str {
        match self {
            GraphNode::Cve { id, .. }
            | GraphNode::CweCluster { id, .. }
            | GraphNode::MsrcProduct { id, .. }
            | GraphNode::Subsystem { id, .. }
            | GraphNode::SyntacticInvariant { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphEdge {
    SemanticSimilar { similarity: f64 },
    StructuralCluster { cwe: String }, // (legacy hub-spoke; relational projection doesn't use it)
    TemporalSpike { window_days: u32 },
    MsrcProduct, // (legacy hub-spoke)
    SyntacticNegated { evidence_count: u64 },
    // Relational projection edges — CVE → CVE direct, directed (high CVSS → low).
    SharesCwe { cwe: String },
    SharesProduct { product: String },
}

/// IPC wire format — carries the edge's endpoints as string IDs.
/// Cytoscape expects `{ data: { source, target, ...edge fields } }`;
/// `#[serde(flatten)]` flattens GraphEdge fields up to the top level.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdgeWire {
    pub from: String,
    pub to: String,
    #[serde(flatten)]
    pub data: GraphEdge,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdgeWire>,
}

/// Incremental update diff. The frontend "graph_diff" event carries this.
/// One signal → one diff; if the diff is empty it isn't emitted (no needless event spam).
#[derive(Debug, Clone, Default, Serialize)]
pub struct GraphDiff {
    pub added_nodes: Vec<GraphNode>,
    pub updated_nodes: Vec<GraphNode>,
    pub added_edges: Vec<GraphEdgeWire>,
}

impl GraphDiff {
    pub fn is_empty(&self) -> bool {
        self.added_nodes.is_empty()
            && self.updated_nodes.is_empty()
            && self.added_edges.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct ProzessGraph {
    inner: DiGraph<GraphNode, GraphEdge>,
    id_to_idx: HashMap<String, NodeIndex>,
}

impl ProzessGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// If called with the same id, overwrites the weight and preserves the NodeIndex.
    /// This way edges aren't broken; only the node payload (cvss, count, etc.) is updated.
    pub fn upsert_node(&mut self, node: GraphNode) -> NodeIndex {
        let id = node.id().to_string();
        if let Some(&idx) = self.id_to_idx.get(&id) {
            self.inner[idx] = node;
            idx
        } else {
            let idx = self.inner.add_node(node);
            self.id_to_idx.insert(id, idx);
            idx
        }
    }

    /// Both endpoints must have been upserted.
    /// If missing, `None` — the caller should add the node first.
    pub fn add_edge(
        &mut self,
        from_id: &str,
        to_id: &str,
        edge: GraphEdge,
    ) -> Option<EdgeIndex> {
        let from = *self.id_to_idx.get(from_id)?;
        let to = *self.id_to_idx.get(to_id)?;
        Some(self.inner.add_edge(from, to, edge))
    }

    /// Serializable flat snapshot for IPC.
    pub fn snapshot(&self) -> GraphSnapshot {
        let nodes: Vec<GraphNode> = self.inner.node_weights().cloned().collect();
        let edges: Vec<GraphEdgeWire> = self
            .inner
            .edge_indices()
            .filter_map(|e| {
                let (a, b) = self.inner.edge_endpoints(e)?;
                let data = self.inner.edge_weight(e)?.clone();
                Some(GraphEdgeWire {
                    from: self.inner[a].id().to_string(),
                    to: self.inner[b].id().to_string(),
                    data,
                })
            })
            .collect();
        GraphSnapshot { nodes, edges }
    }

    pub fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.id_to_idx.contains_key(id)
    }

    /// Apply the signal coming from the bus to the graph, return whatever changed as a diff.
    ///
    /// Right now only ingestion signals (nvd_ingestion / msrc_ingestion) grow the
    /// graph. user_decision signals affect Prokaryotes coherence but
    /// don't touch the graph shape (if decided/skipped node coloring is added later
    /// it would become visible here too).
    ///
    /// **Source preservation:** the existing node's source is preserved — if a CVE
    /// first gets a signal from NVD, then from MSRC, the source stays "NVD" (first-write-wins).
    /// Only cvss is updated.
    pub fn apply_signal(&mut self, signal: &LayerSignal) -> GraphDiff {
        let mut diff = GraphDiff::default();

        let new_source = match signal.source.as_str() {
            "nvd_ingestion" => "NVD",
            "msrc_ingestion" => "MSRC",
            _ => return diff,
        };

        let cve_id = signal.case_id.clone();
        let cvss = Some((signal.delta * 10.0).clamp(0.0, 10.0));

        let final_source = if let Some(idx) = self.id_to_idx.get(&cve_id) {
            match &self.inner[*idx] {
                GraphNode::Cve { source, .. } => source.clone(),
                _ => new_source.to_string(),
            }
        } else {
            new_source.to_string()
        };

        let existed = self.contains(&cve_id);
        let node = GraphNode::Cve {
            id: cve_id,
            cvss,
            source: final_source,
        };
        self.upsert_node(node.clone());

        if existed {
            diff.updated_nodes.push(node);
        } else {
            diff.added_nodes.push(node);
        }

        diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Layer;

    #[test]
    fn upsert_and_snapshot() {
        let mut g = ProzessGraph::new();
        g.upsert_node(GraphNode::Cve {
            id: "CVE-2026-31444".to_string(),
            cvss: Some(9.8),
            source: "NVD".to_string(),
        });
        g.upsert_node(GraphNode::CweCluster {
            id: "cluster:CWE-416".to_string(),
            cwe: "CWE-416".to_string(),
            member_count: 1,
        });
        let e = g.add_edge(
            "CVE-2026-31444",
            "cluster:CWE-416",
            GraphEdge::StructuralCluster {
                cwe: "CWE-416".to_string(),
            },
        );
        assert!(e.is_some());

        let snap = g.snapshot();
        assert_eq!(snap.nodes.len(), 2);
        assert_eq!(snap.edges.len(), 1);
        assert_eq!(snap.edges[0].from, "CVE-2026-31444");
        assert_eq!(snap.edges[0].to, "cluster:CWE-416");
    }

    #[test]
    fn upsert_updates_existing_preserves_index() {
        let mut g = ProzessGraph::new();
        g.upsert_node(GraphNode::Cve {
            id: "CVE-X".to_string(),
            cvss: Some(5.0),
            source: "NVD".to_string(),
        });
        g.upsert_node(GraphNode::Cve {
            id: "CVE-X".to_string(),
            cvss: Some(9.0),
            source: "NVD".to_string(),
        });
        assert_eq!(g.node_count(), 1);

        let snap = g.snapshot();
        match &snap.nodes[0] {
            GraphNode::Cve { cvss, .. } => assert_eq!(*cvss, Some(9.0)),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn add_edge_missing_endpoint_returns_none() {
        let mut g = ProzessGraph::new();
        g.upsert_node(GraphNode::Cve {
            id: "CVE-A".to_string(),
            cvss: None,
            source: "NVD".to_string(),
        });
        let e = g.add_edge(
            "CVE-A",
            "CVE-MISSING",
            GraphEdge::SemanticSimilar { similarity: 0.9 },
        );
        assert!(e.is_none());
    }

    #[test]
    fn edge_wire_serializes_flat() {
        let wire = GraphEdgeWire {
            from: "a".to_string(),
            to: "b".to_string(),
            data: GraphEdge::SemanticSimilar { similarity: 0.84 },
        };
        let json = serde_json::to_value(&wire).unwrap();
        assert_eq!(json["from"], "a");
        assert_eq!(json["to"], "b");
        assert_eq!(json["kind"], "semantic_similar");
        assert!((json["similarity"].as_f64().unwrap() - 0.84).abs() < 1e-9);
    }

    #[test]
    fn apply_signal_adds_new_cve_from_nvd() {
        let mut g = ProzessGraph::new();
        let sig = LayerSignal::new("CVE-NEW-001", Layer::Mikro, "nvd_ingestion", 0.95);
        let diff = g.apply_signal(&sig);

        assert_eq!(diff.added_nodes.len(), 1);
        assert_eq!(diff.updated_nodes.len(), 0);
        assert_eq!(g.node_count(), 1);
        match &diff.added_nodes[0] {
            GraphNode::Cve { id, cvss, source } => {
                assert_eq!(id, "CVE-NEW-001");
                assert!((cvss.unwrap() - 9.5).abs() < 1e-9);
                assert_eq!(source, "NVD");
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn apply_signal_updates_existing_cve_preserves_source() {
        let mut g = ProzessGraph::new();
        g.upsert_node(GraphNode::Cve {
            id: "CVE-X".to_string(),
            cvss: Some(5.0),
            source: "NVD".to_string(),
        });
        let sig = LayerSignal::new("CVE-X", Layer::Mikro, "msrc_ingestion", 0.85);
        let diff = g.apply_signal(&sig);

        assert_eq!(diff.added_nodes.len(), 0);
        assert_eq!(diff.updated_nodes.len(), 1);
        match &diff.updated_nodes[0] {
            GraphNode::Cve { source, cvss, .. } => {
                assert_eq!(source, "NVD", "source must be preserved on update");
                assert!((cvss.unwrap() - 8.5).abs() < 1e-9);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn apply_signal_user_decision_no_graph_change() {
        let mut g = ProzessGraph::new();
        g.upsert_node(GraphNode::Cve {
            id: "CVE-A".to_string(),
            cvss: Some(8.0),
            source: "NVD".to_string(),
        });
        let sig = LayerSignal::new("CVE-A", Layer::Lokal, "user_decision", 0.05);
        let diff = g.apply_signal(&sig);

        assert!(diff.is_empty());
        assert_eq!(g.node_count(), 1);
    }
}
