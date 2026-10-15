// invariant.rs - Prokaryotes' fixed point unit

use crate::decision::DecisionOutcome;

#[derive(Debug, Clone)]
pub struct Invariant {
    pub id: String,
    pub outcome: DecisionOutcome,
    pub absorbed_at: u64,  // timestamp (unix)
}

impl Invariant {
    pub fn new(id: &str, outcome: DecisionOutcome) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id: id.to_string(),
            outcome,
            absorbed_at: ts, 
        }
    }
}
