use rusqlite::{Connection, Result, params};
use crate::decision::{BinaryDecision, DecisionOutcome};
use crate::Prokaryotes;

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS prokaryotes_decisions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                delta_id    TEXT NOT NULL,
                outcome     INTEGER NOT NULL,
                timestamp   INTEGER NOT NULL
            );
        ")?;
        Ok(Self { conn })
    }

    pub fn save_decision(&self, decision: &BinaryDecision) -> Result<()> {
        self.conn.execute(
            "INSERT INTO prokaryotes_decisions (delta_id, outcome, timestamp)
             VALUES (?1, ?2, ?3)",
            params![
                decision.delta_id,
                decision.outcome as i64,
                decision.timestamp as i64,
            ],
        )?;
        Ok(())
    }

    pub fn load_decisions(&self) -> Result<Vec<BinaryDecision>> {
        let mut stmt = self.conn.prepare(
            "SELECT delta_id, outcome, timestamp
             FROM prokaryotes_decisions
             ORDER BY id ASC"
        )?;
        let decisions = stmt.query_map([], |row| {
            let outcome_int: i64 = row.get(1)?;
            let outcome = if outcome_int == 1 {
                DecisionOutcome::Opportunity
            } else {
                DecisionOutcome::Noise
            };
            Ok(BinaryDecision {
                delta_id:  row.get(0)?,
                outcome,
                timestamp: row.get::<_, i64>(2)? as u64,
            })
        })?
        .collect::<Result<Vec<_>>>()?;
        Ok(decisions)
    }

    pub fn decision_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM prokaryotes_decisions",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn restore_prokaryotes(&self) -> Result<Prokaryotes> {
        let mut p = Prokaryotes::new();
        let decisions = self.load_decisions()?;
        for decision in &decisions {
            p.absorb(&decision.delta_id, decision.outcome);
        }
        eprintln!(
            "[prokaryotes] restored: {} decisions, {} invariants, coherence={:.4}, epsilon={:.4}",
            decisions.len(),
            p.size(),
            p.coherence.value(),
            p.epsilon()
        );
        Ok(p)
    }
}
