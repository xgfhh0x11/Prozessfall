// LayerSignal — the canonical output format Prozessfall uses to talk to the outside world.
// [case_id | layer | source | delta] — the spec's fundamental signal unit.
//
// Layer: tells which abstraction level the signal sits at.
// Source: the channel the signal came from (NVD/MSRC/structural/semantic/syntactic/user_decision).
// Delta: the numeric effect this signal adds to the system state (coherence change, etc.).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Makro,
    Mezo,
    Mikro,
    Lokal,
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerSignal {
    pub case_id: String,
    pub layer: Layer,
    pub source: String,
    pub delta: f64,
}

impl LayerSignal {
    pub fn new(case_id: impl Into<String>, layer: Layer, source: impl Into<String>, delta: f64) -> Self {
        Self {
            case_id: case_id.into(),
            layer,
            source: source.into(),
            delta,
        }
    }
}
