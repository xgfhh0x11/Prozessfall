// syntactic.rs — Syntactic Invariant (Skeleton)
// Observes Prokaryotes T → t' transitions.
// Produces negative space claims: "definitely not Y"
// As the system grows, this skeleton will fill itself in.
 
use crate::Prokaryotes;
 
/// Negative space claim.
/// "This pattern is definitely not that class."
#[derive(Debug, Clone)]
pub struct NegationClaim {
    pub pattern:        String,  // which pattern
    pub negated_class:  String,  // definitely not this
    pub evidence_count: u64,     // how many Prokaryotes transitions it came from
}
 
/// Syntactic invariant layer.
/// Revolves around Prokaryotes, observing its T → t' transitions.
/// Narrows the opportunity space — semantic correlation runs on the narrowed space.
pub struct SyntacticInvariant {
    pub negations: Vec<NegationClaim>,
    observation_count: u64,
}
 
impl SyntacticInvariant {
    pub fn new() -> Self {
        Self {
            negations: Vec::new(),
            observation_count: 0,
        }
    }
 
    /// Observe the Prokaryotes state.
    /// What stays unchanged in the T → t' transition → NegationClaim candidate.
    /// Stub for now — will fill in as the system grows.
    pub fn observe(&mut self, _prokaryotes: &Prokaryotes) {
        self.observation_count += 1;
        // TODO: diff between T and t'
        // TODO: absorb unchanged patterns as NegationClaim
        // TODO: handles + scheduler context will come here
    }
 
    /// Is there a negative claim for this delta?
    /// If so → the opportunity space excludes this class.
    pub fn is_negated(&self, pattern: &str, class: &str) -> bool {
        self.negations.iter().any(|n| {
            n.pattern == pattern && n.negated_class == class
        })
    }
 
    /// How many observations were made?
    pub fn observation_count(&self) -> u64 {
        self.observation_count
    }
 
    /// How many negation claims are there?
    pub fn negation_count(&self) -> usize {
        self.negations.len()
    }
 
    /// Status — what does the skeleton know right now?
    pub fn status(&self) {
        println!(
            "[syntactic] observations={} negations={} (skeleton)",
            self.observation_count,
            self.negations.len()
        );
    }
}
 
impl Default for SyntacticInvariant {
    fn default() -> Self {
        Self::new()
    }
}
