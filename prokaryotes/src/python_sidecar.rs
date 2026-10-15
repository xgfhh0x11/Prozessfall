// Python sidecar supervisor — JSON-RPC over a long-running child process.
//
// Two layers:
//   - PythonSidecar: low-level wrapper of a single child process (spawn + call + drop).
//     The IO mutex keeps request/response atomic.
//   - SidecarHandle: high-level handle wrapping PythonSidecar.
//     Stores the spawn config, auto-restarts on a pipe error (with a 10s cooldown).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::Value;

const RESTART_COOLDOWN: Duration = Duration::from_secs(10);

struct SidecarIO {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

pub struct PythonSidecar {
    child: Mutex<Child>,
    io: Mutex<SidecarIO>,
    label: String,
}

impl PythonSidecar {
    pub fn spawn(label: &str, python: &str, script: &Path) -> std::io::Result<Self> {
        let mut child = Command::new(python)
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("sidecar stdin pipe missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("sidecar stdout pipe missing"))?;
        let stdout = BufReader::new(stdout);

        let sidecar = Self {
            child: Mutex::new(child),
            io: Mutex::new(SidecarIO { stdin, stdout }),
            label: label.to_string(),
        };

        // Ready handshake.
        let ready = sidecar.read_response().map_err(std::io::Error::other)?;
        let status = ready.get("status").and_then(|s| s.as_str());
        if status != Some("ready") {
            return Err(std::io::Error::other(format!(
                "sidecar {} unexpected ready response: {}",
                label, ready
            )));
        }
        eprintln!("[sidecar] {} ready", label);
        Ok(sidecar)
    }

    pub fn call(&self, cmd: Value) -> Result<Value, String> {
        let mut io = self.io.lock().map_err(|e| e.to_string())?;
        let line = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
        writeln!(io.stdin, "{}", line).map_err(|e| e.to_string())?;
        io.stdin.flush().map_err(|e| e.to_string())?;

        let mut resp_line = String::new();
        io.stdout
            .read_line(&mut resp_line)
            .map_err(|e| e.to_string())?;
        if resp_line.is_empty() {
            return Err(format!("sidecar {} closed stdout", self.label));
        }
        serde_json::from_str(&resp_line).map_err(|e| format!("bad sidecar response: {}", e))
    }

    fn read_response(&self) -> Result<Value, String> {
        let mut io = self.io.lock().map_err(|e| e.to_string())?;
        let mut line = String::new();
        io.stdout.read_line(&mut line).map_err(|e| e.to_string())?;
        if line.is_empty() {
            return Err("sidecar closed stdout before ready".to_string());
        }
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }
}

impl Drop for PythonSidecar {
    fn drop(&mut self) {
        if let Ok(mut io) = self.io.lock() {
            let _ = writeln!(io.stdin, "{{\"cmd\":\"quit\"}}");
            let _ = io.stdin.flush();
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        eprintln!("[sidecar] {} stopped", self.label);
    }
}

// ──────────────────────────────────────────────────────────────────
// SidecarHandle — auto-restart wrapper
// ──────────────────────────────────────────────────────────────────

pub struct SidecarHandle {
    label: String,
    python: String,
    script: PathBuf,
    inner: RwLock<PythonSidecar>,
    last_restart: Mutex<Option<Instant>>,
}

impl SidecarHandle {
    pub fn spawn(label: &str, python: &str, script: PathBuf) -> std::io::Result<Self> {
        let inner = PythonSidecar::spawn(label, python, &script)?;
        Ok(Self {
            label: label.to_string(),
            python: python.to_string(),
            script,
            inner: RwLock::new(inner),
            last_restart: Mutex::new(None),
        })
    }

    pub fn call(&self, cmd: Value) -> Result<Value, String> {
        let first = {
            let guard = self.inner.read().map_err(|e| e.to_string())?;
            guard.call(cmd.clone())
        };

        match first {
            Ok(v) => Ok(v),
            Err(e) if is_pipe_error(&e) => {
                eprintln!(
                    "[sidecar-handle] {} pipe error, attempting restart: {}",
                    self.label, e
                );
                self.try_restart()?;
                let guard = self.inner.read().map_err(|e| e.to_string())?;
                guard.call(cmd)
            }
            Err(e) => Err(e),
        }
    }

    fn try_restart(&self) -> Result<(), String> {
        let mut last_restart = self.last_restart.lock().map_err(|e| e.to_string())?;
        if let Some(t) = *last_restart {
            if t.elapsed() < RESTART_COOLDOWN {
                return Err(format!(
                    "sidecar {} restart cooldown active ({}s remaining)",
                    self.label,
                    (RESTART_COOLDOWN - t.elapsed()).as_secs()
                ));
            }
        }
        // Mark attempt regardless of outcome → a spawn failure also enters the cooldown.
        *last_restart = Some(Instant::now());

        let new = PythonSidecar::spawn(&self.label, &self.python, &self.script)
            .map_err(|e| format!("restart spawn failed: {}", e))?;
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        *guard = new;
        eprintln!("[sidecar-handle] {} restarted", self.label);
        Ok(())
    }
}

fn is_pipe_error(e: &str) -> bool {
    e.contains("closed stdout")
        || e.contains("Broken pipe")
        || e.contains("broken pipe")
        || e.contains("os error 32")
}
