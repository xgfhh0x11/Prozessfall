// decision.rs — Binary decision mechanism
 
use serde::{Deserialize, Serialize};
 
/// 0 = error (noise), 1 = opportunity
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Noise = 0,
    Opportunity = 1,
}
 
impl TryFrom<u8> for DecisionOutcome {
    type Error = &'static str;
 
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(DecisionOutcome::Noise),
            1 => Ok(DecisionOutcome::Opportunity),
            _ => Err("invalid binary decision: must be 0 or 1"),
        }
    }
}
 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDecision {
    pub delta_id: String,
    pub outcome: DecisionOutcome,
    pub timestamp: u64,
}
 
impl BinaryDecision {
    pub fn new(delta_id: &str, outcome: DecisionOutcome) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            delta_id: delta_id.to_string(),
            outcome,
            timestamp: ts,
        }
    }
}
