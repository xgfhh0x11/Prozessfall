// main.rs — Prokaryotes interface
// Two modes:
//   normal: terminal interactive
//   --json: Python FFI bridge (stdin JSON → stdout JSON)

use prokaryotes::{Prokaryotes, Storage, DecisionOutcome, BinaryDecision};
use std::io::{self, BufRead, Write};

const DB_PATH: &str = "/home/tylersec/prozessfall/prokaryotes/prokaryotes.db";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.contains(&"--json".to_string());

    if json_mode {
        run_json_bridge();
    } else {
        run_terminal();
    }
}

fn run_json_bridge() {
    let storage = match Storage::open(DB_PATH) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", serde_json::json!({"status": "error", "msg": format!("{}", e)}));
            return;
        }
    };

    let mut prokaryotes = match storage.restore_prokaryotes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", serde_json::json!({"status": "error", "msg": format!("{}", e)}));
            return;
        }
    };

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => break,
        };

        if line.is_empty() { continue; }

        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", serde_json::json!({
                    "status": "error",
                    "msg": format!("JSON parse error: {}", e)
                }));
                continue;
            }
        };

        if let Some(cmd) = parsed.get("cmd").and_then(|v| v.as_str()) {
            match cmd {
                "status" => {
                    println!("{}", serde_json::json!({
                        "status": "ok",
                        "coherence": prokaryotes.coherence.value(),
                        "epsilon": prokaryotes.epsilon(),
                        "invariants": prokaryotes.size(),
                        "decisions": storage.decision_count().unwrap_or(0)
                    }));
                }
                "quit" => {
                    println!("{}", serde_json::json!({"status": "bye"}));
                    break;
                }
                _ => {
                    println!("{}", serde_json::json!({
                        "status": "error",
                        "msg": format!("unknown cmd: {}", cmd)
                    }));
                }
            }
            io::stdout().flush().ok();
            continue;
        }

        let delta_id = match parsed.get("delta_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => {
                println!("{}", serde_json::json!({"status": "error", "msg": "delta_id required"}));
                io::stdout().flush().ok();
                continue;
            }
        };

        let outcome_int = match parsed.get("outcome").and_then(|v| v.as_u64()) {
            Some(n) => n,
            None => {
                println!("{}", serde_json::json!({"status": "error", "msg": "outcome required (0 or 1)"}));
                io::stdout().flush().ok();
                continue;
            }
        };

        let outcome = match DecisionOutcome::try_from(outcome_int as u8) {
            Ok(o) => o,
            Err(e) => {
                println!("{}", serde_json::json!({"status": "error", "msg": e}));
                io::stdout().flush().ok();
                continue;
            }
        };

        let decision = BinaryDecision::new(&delta_id, outcome);
        if let Err(e) = storage.save_decision(&decision) {
            println!("{}", serde_json::json!({"status": "error", "msg": format!("DB error: {}", e)}));
            io::stdout().flush().ok();
            continue;
        }

        prokaryotes.absorb(&delta_id, outcome);

        println!("{}", serde_json::json!({
            "status": "ok",
            "delta_id": delta_id,
            "outcome": outcome_int,
            "coherence": prokaryotes.coherence.value(),
            "epsilon": prokaryotes.epsilon(),
            "invariants": prokaryotes.size()
        }));
        io::stdout().flush().ok();
    }
}

fn run_terminal() {
    println!("╔══════════════════════════════════════╗");
    println!("║         PROKARYOTES v0.1.0           ║");
    println!("║   0 = noise  |  1 = opportunity      ║");
    println!("║   q = quit   |  s = status            ║");
    println!("╚══════════════════════════════════════╝\n");

    let storage = Storage::open(DB_PATH).expect("could not open DB");
    let mut prokaryotes = storage.restore_prokaryotes().expect("restore failed");

    println!(
        "State: {} decisions, {} invariants, coherence={:.4}, epsilon={:.4}\n",
        storage.decision_count().unwrap_or(0),
        prokaryotes.size(),
        prokaryotes.coherence.value(),
        prokaryotes.epsilon()
    );

    let stdin = io::stdin();
    let mut input_count = 0u64;

    loop {
        print!("delta_id> ");
        io::stdout().flush().unwrap();

        let mut delta_id = String::new();
        if stdin.lock().read_line(&mut delta_id).unwrap() == 0 { break; }
        let delta_id = delta_id.trim().to_string();

        if delta_id.is_empty() { continue; }
        if delta_id == "q" || delta_id == "quit" { println!("Exiting."); break; }
        if delta_id == "s" || delta_id == "status" {
            print_status(&prokaryotes, &storage);
            continue;
        }

        print!("decision (0/1)> ");
        io::stdout().flush().unwrap();

        let mut decision_str = String::new();
        if stdin.lock().read_line(&mut decision_str).unwrap() == 0 { break; }
        let decision_str = decision_str.trim();

        let outcome = match decision_str {
            "0" => DecisionOutcome::Noise,
            "1" => DecisionOutcome::Opportunity,
            _ => { println!("Invalid. Enter 0 or 1.\n"); continue; }
        };

        let decision = BinaryDecision::new(&delta_id, outcome);
        if let Err(e) = storage.save_decision(&decision) {
            println!("[!] DB error: {}", e);
            continue;
        }

        prokaryotes.absorb(&delta_id, outcome);
        input_count += 1;

        let marker = match outcome {
            DecisionOutcome::Opportunity => "⚡ OPPORTUNITY",
            DecisionOutcome::Noise      => "   noise",
        };

        println!(
            "{} → coherence={:.4}  epsilon={:.4}  invariants={}\n",
            marker,
            prokaryotes.coherence.value(),
            prokaryotes.epsilon(),
            prokaryotes.size()
        );
    }

    println!("\nSession: {} decisions. Total invariants: {}", input_count, prokaryotes.size());
}

fn print_status(p: &Prokaryotes, storage: &Storage) {
    println!("\n--- PROKARYOTES STATUS ---");
    println!("Decisions    : {}", storage.decision_count().unwrap_or(0));
    println!("Invariant    : {}", p.size());
    println!("Coherence    : {:.4}", p.coherence.value());
    println!("Epsilon      : {:.4}", p.epsilon());
    if !p.invariants.is_empty() {
        println!("\nAbsorbed invariants:");
        for inv in &p.invariants {
            let outcome = match inv.outcome {
                DecisionOutcome::Opportunity => "opportunity",
                DecisionOutcome::Noise       => "noise",
            };
            println!("  [{}] {} @ {}", outcome, inv.id, inv.absorbed_at);
        }
    }
    println!();
}
