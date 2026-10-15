// Config — loads config.toml into the Rust side.
//
// Discovery order:
//   1. $PROZESSFALL_CONFIG env var (override, explicit escape hatch)
//   2. Exe dir → upward search → first config.toml found
// In dev, 5 levels up from `target/debug/prozessfall-ui` → project root.
// May differ in a production bundle — app_data_dir integration in Phase 6+.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub paths: Paths,
    pub python: Python,
    pub event_bus: EventBus,
    pub ingestion: Ingestion,
}

#[derive(Debug, Deserialize)]
pub struct Paths {
    // prokaryotes_bin is for the Python side, Rust doesn't use it — serde silently ignores it.
    pub prozessfall_db: PathBuf,
    pub prokaryotes_db: PathBuf,
    pub sidecars: SidecarPaths,
}

#[derive(Debug, Deserialize)]
pub struct SidecarPaths {
    pub nvd: PathBuf,
    pub msrc: PathBuf,
    pub vault: PathBuf,
    pub semantic: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Python {
    pub bin: String,
}

#[derive(Debug, Deserialize)]
pub struct EventBus {
    pub capacity: usize,
}

#[derive(Debug, Deserialize)]
pub struct Ingestion {
    pub nvd: NvdIngestion,
    pub msrc: MsrcIngestion,
}

#[derive(Debug, Deserialize)]
pub struct NvdIngestion {
    pub periodic_grace_secs: u64,
    pub periodic_interval_secs: u64,
    pub periodic_days_back: u32,
}

#[derive(Debug, Deserialize)]
pub struct MsrcIngestion {
    pub periodic_grace_secs: u64,
    pub periodic_interval_secs: u64,
    pub periodic_months_back: u32,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("config read failed ({}): {}", path.display(), e))?;
        toml::from_str(&raw).map_err(|e| format!("config parse failed: {}", e))
    }

    pub fn discover() -> Result<Self, String> {
        if let Ok(env_path) = std::env::var("PROZESSFALL_CONFIG") {
            return Self::load(Path::new(&env_path));
        }

        let exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {}", e))?;
        let mut here = exe
            .parent()
            .ok_or("exe has no parent dir")?
            .to_path_buf();
        loop {
            let candidate = here.join("config.toml");
            if candidate.exists() {
                eprintln!("[config] using {}", candidate.display());
                return Self::load(&candidate);
            }
            if !here.pop() {
                break;
            }
        }
        Err(
            "config.toml not found in ancestor dirs (set $PROZESSFALL_CONFIG to override)"
                .to_string(),
        )
    }
}
