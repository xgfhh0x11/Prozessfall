// Prokaryotes — Fixed Point Core
// The immutable core of the Prozessfall intelligence infrastructure.

pub mod invariant;
pub mod decision;
pub mod coherence;
pub mod storage;
pub mod syntactic;
pub mod layer_signal;
pub mod surface;
pub mod graph;
pub mod graph_projection;
pub mod python_sidecar;
pub mod config;

pub use invariant::Invariant;
pub use decision::{BinaryDecision, DecisionOutcome};
pub use coherence::Coherence;
pub use storage::Storage;
pub use syntactic::SyntacticInvariant;
pub use layer_signal::{Layer, LayerSignal};
pub use surface::{SurfaceEntry, SurfaceState};
pub use graph::{GraphDiff, GraphEdge, GraphEdgeWire, GraphNode, GraphSnapshot, ProzessGraph};
pub use graph_projection::project_from_db;

/// Prokaryotes' fixed point condition:
/// ||P_{n+1} - P_n|| < epsilon_n
/// epsilon_n = 1 / (1 + coherence_n)
pub struct Prokaryotes {
    pub invariants: Vec<Invariant>,
    pub coherence: Coherence,
}

impl Prokaryotes {
    pub fn new() -> Self {
        Self {
            invariants: Vec::new(),
            coherence: Coherence::new(),
        }
    }

    /// Add a binary decision, update the fixed point.
    pub fn absorb(&mut self, delta_id: &str, outcome: DecisionOutcome) {
        self.coherence.record(delta_id, outcome);
        let epsilon = self.epsilon();
        let coherence_val = self.coherence.value();

        // Convergence check
        if coherence_val > (1.0 - epsilon) {
            // This invariant is stable — absorb it
            if !self.invariants.iter().any(|i| i.id == delta_id) {
                self.invariants.push(Invariant::new(delta_id, outcome));
            }
        }
    }

    /// epsilon_n = 1 / (1 + coherence_n)
    pub fn epsilon(&self) -> f64 {
        1.0 / (1.0 + self.coherence.value())
    }

    /// How many invariants were absorbed?
    pub fn size(&self) -> usize {
        self.invariants.len()
    }
}

impl Default for Prokaryotes {
    fn default() -> Self {
        Self::new()
    }
}
