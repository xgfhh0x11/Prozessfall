// SurfaceState — in-memory snapshot of the opportunity space.
// Phase 1.3 minimum viable: filled by user_decision signals.
// Phase 1.4+: real surface fill kicks in once ingestion + correlation events are added.
//
// Design rule: sync, no IO, no async. Async wrapping happens on the src-tauri side.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Layer, LayerSignal};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceEntry {
    pub case_id: String,
    pub layer: Layer,
    pub source: String,
    pub delta: f64,
    pub absorbed_count: u64,
    pub last_updated_ts: u64,
}

#[derive(Debug, Default)]
pub struct SurfaceState {
    entries: BTreeMap<String, SurfaceEntry>,
}

impl SurfaceState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Upsert by case_id when a new signal arrives.
    /// If the same case_id was seen before, update the delta and increment the counter.
    pub fn upsert(&mut self, signal: &LayerSignal, ts: u64) {
        self.entries
            .entry(signal.case_id.clone())
            .and_modify(|e| {
                e.delta = signal.delta;
                e.layer = signal.layer;
                e.source = signal.source.clone();
                e.absorbed_count += 1;
                e.last_updated_ts = ts;
            })
            .or_insert_with(|| SurfaceEntry {
                case_id: signal.case_id.clone(),
                layer: signal.layer,
                source: signal.source.clone(),
                delta: signal.delta,
                absorbed_count: 1,
                last_updated_ts: ts,
            });
    }

    /// Top-K in descending order by |delta| magnitude.
    /// Scoring may change in the future (recency, layer weight, etc.).
    pub fn top_k(&self, k: usize) -> Vec<SurfaceEntry> {
        let mut items: Vec<SurfaceEntry> = self.entries.values().cloned().collect();
        items.sort_by(|a, b| {
            b.delta
                .abs()
                .partial_cmp(&a.delta.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        items.truncate(k);
        items
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
