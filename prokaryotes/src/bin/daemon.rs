// Prozessfall daemon — axum HTTP + WebSocket server.
//
// Web equivalent of the existing Tauri commands. Same AppState shape, same bus,
// same sidecar supervisor — only the IPC boundary changed (Tauri invoke/emit →
// REST + WebSocket).
//
// Bind: 127.0.0.1:8080 (localhost-only, no external port).
// The Vite dev server (:1420) proxies the /api/* and /ws paths here — the browser
// sees a single origin, no CORS.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use prokaryotes::{
    config::Config,
    project_from_db,
    python_sidecar::SidecarHandle,
    BinaryDecision, DecisionOutcome, GraphDiff, GraphSnapshot, Layer, LayerSignal, Prokaryotes,
    ProzessGraph, Storage, SurfaceEntry, SurfaceState,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

const BIND_ADDR: &str = "127.0.0.1:8080";

struct AppState {
    prokaryotes: Mutex<Prokaryotes>,
    storage: Mutex<Storage>,
    surface: Arc<RwLock<SurfaceState>>,
    graph: Arc<RwLock<ProzessGraph>>,
    signal_tx: broadcast::Sender<LayerSignal>,
    diff_tx: broadcast::Sender<GraphDiff>,
    nvd_sidecar: Arc<SidecarHandle>,
    msrc_sidecar: Arc<SidecarHandle>,
    vault_sidecar: Arc<SidecarHandle>,
    // Held alive so its child process stays running for the daemon's lifetime,
    // even though semantic compute is only called once at startup.
    _semantic_sidecar: Arc<SidecarHandle>,
}

// ──────────────────────────────────────────────────────────────────
// HTTP route handlers
// ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProkaryotesSnapshot {
    coherence: f64,
    epsilon: f64,
    invariants: usize,
    decision_count: usize,
}

async fn get_state(State(state): State<Arc<AppState>>) -> Json<ProkaryotesSnapshot> {
    let p = state.prokaryotes.lock().expect("prokaryotes mutex poisoned");
    Json(ProkaryotesSnapshot {
        coherence: p.coherence.value(),
        epsilon: p.epsilon(),
        invariants: p.size(),
        decision_count: p.coherence.decision_count(),
    })
}

#[derive(Deserialize)]
struct AbsorbReq {
    delta_id: String,
    outcome: u8,
}

async fn absorb_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AbsorbReq>,
) -> Result<Json<LayerSignal>, (StatusCode, String)> {
    let outcome = DecisionOutcome::try_from(req.outcome)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let coherence_before = {
        let p = state.prokaryotes.lock().expect("prokaryotes mutex poisoned");
        p.coherence.value()
    };

    let decision = BinaryDecision::new(&req.delta_id, outcome);
    {
        let storage = state.storage.lock().expect("storage mutex poisoned");
        storage
            .save_decision(&decision)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let coherence_after = {
        let mut p = state.prokaryotes.lock().expect("prokaryotes mutex poisoned");
        p.absorb(&req.delta_id, outcome);
        p.coherence.value()
    };

    let signal = LayerSignal::new(
        req.delta_id,
        Layer::Lokal,
        "user_decision",
        coherence_after - coherence_before,
    );

    let _ = state.signal_tx.send(signal.clone());
    Ok(Json(signal))
}

#[derive(Deserialize)]
struct SurfaceQuery {
    #[serde(default = "default_k")]
    k: usize,
}
fn default_k() -> usize {
    20
}

async fn surface_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SurfaceQuery>,
) -> Json<Vec<SurfaceEntry>> {
    let s = state.surface.read().expect("surface lock poisoned");
    Json(s.top_k(q.k))
}

async fn graph_handler(State(state): State<Arc<AppState>>) -> Json<GraphSnapshot> {
    let g = state.graph.read().expect("graph lock poisoned");
    Json(g.snapshot())
}

#[derive(Deserialize)]
struct NvdReq {
    days_back: u32,
}

async fn ingest_nvd_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NvdReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    run_ingestion_fetch(
        state.nvd_sidecar.clone(),
        state.signal_tx.clone(),
        serde_json::json!({"cmd": "fetch_delta", "days_back": req.days_back}),
        "nvd_ingestion",
    )
    .await
    .map(Json)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
struct MsrcReq {
    months_back: u32,
}

async fn ingest_msrc_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MsrcReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    run_ingestion_fetch(
        state.msrc_sidecar.clone(),
        state.signal_tx.clone(),
        serde_json::json!({"cmd": "fetch_delta", "months_back": req.months_back}),
        "msrc_ingestion",
    )
    .await
    .map(Json)
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
struct VaultDraftReq {
    case_id: String,
    subsystem: Option<String>,
}

async fn vault_draft_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VaultDraftReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let sidecar = state.vault_sidecar.clone();
    let mut params = serde_json::json!({
        "cmd": "draft",
        "case_id": req.case_id,
    });
    if let Some(s) = req.subsystem {
        params["subsystem"] = serde_json::Value::String(s);
    }
    tokio::task::spawn_blocking(move || sidecar.call(params))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("vault join: {}", e)))?
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn run_ingestion_fetch(
    sidecar: Arc<SidecarHandle>,
    signal_tx: broadcast::Sender<LayerSignal>,
    params: serde_json::Value,
    default_source: &'static str,
) -> Result<serde_json::Value, String> {
    let resp = tokio::task::spawn_blocking(move || sidecar.call(params))
        .await
        .map_err(|e| format!("ingestion join: {}", e))??;

    if let Some(cves) = resp.get("cves").and_then(|v| v.as_array()) {
        for cve in cves {
            let cve_id = cve
                .get("cve_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let cvss = cve.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let source = cve
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or(default_source)
                .to_string();
            let signal = LayerSignal::new(cve_id, Layer::Mikro, source, cvss / 10.0);
            let _ = signal_tx.send(signal);
        }
    }
    Ok(resp)
}

// ──────────────────────────────────────────────────────────────────
// WebSocket handler — bus → JSON envelope → client
// ──────────────────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut signal_rx = state.signal_tx.subscribe();
    let mut diff_rx = state.diff_tx.subscribe();

    eprintln!("[ws] client connected");

    loop {
        tokio::select! {
            sig = signal_rx.recv() => {
                match sig {
                    Ok(s) => {
                        let env = serde_json::json!({"type": "layer_signal", "payload": s});
                        if sender.send(Message::Text(env.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            diff = diff_rx.recv() => {
                match diff {
                    Ok(d) => {
                        let env = serde_json::json!({"type": "graph_diff", "payload": d});
                        if sender.send(Message::Text(env.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore client messages (no client→server protocol yet)
                    Some(Err(_)) => break,
                }
            }
        }
    }

    eprintln!("[ws] client disconnected");
}

// ──────────────────────────────────────────────────────────────────
// main — wiring identical to old src-tauri/lib.rs run()
// ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::discover()?;

    let storage = Storage::open(
        cfg.paths
            .prokaryotes_db
            .to_str()
            .ok_or("prokaryotes_db path not UTF-8")?,
    )?;
    let prokaryotes = storage.restore_prokaryotes()?;

    let (signal_tx, _) = broadcast::channel::<LayerSignal>(cfg.event_bus.capacity);
    let (diff_tx, _) = broadcast::channel::<GraphDiff>(cfg.event_bus.capacity);
    let surface = Arc::new(RwLock::new(SurfaceState::new()));

    let graph = Arc::new(RwLock::new(project_from_db(&cfg.paths.prozessfall_db)?));

    let nvd_sidecar = Arc::new(SidecarHandle::spawn(
        "nvd",
        &cfg.python.bin,
        cfg.paths.sidecars.nvd.clone(),
    )?);
    let msrc_sidecar = Arc::new(SidecarHandle::spawn(
        "msrc",
        &cfg.python.bin,
        cfg.paths.sidecars.msrc.clone(),
    )?);
    let vault_sidecar = Arc::new(SidecarHandle::spawn(
        "vault",
        &cfg.python.bin,
        cfg.paths.sidecars.vault.clone(),
    )?);
    let semantic_sidecar = Arc::new(SidecarHandle::spawn(
        "semantic",
        &cfg.python.bin,
        cfg.paths.sidecars.semantic.clone(),
    )?);

    // Semantic edges — one-time compute at startup + inject into the graph.
    // cve_embeddings is static (the Python script produced it once), periodic refresh
    // isn't needed. The embedded count is small (500), threshold 0.80 → ~32 edges added.
    {
        let sidecar = semantic_sidecar.clone();
        let resp = tokio::task::spawn_blocking(move || {
            sidecar.call(serde_json::json!({"cmd": "compute", "threshold": 0.80}))
        })
        .await
        .map_err(|e| format!("semantic join: {}", e))?;
        match resp {
            Ok(v) => {
                if let Some(edges) = v.get("edges").and_then(|x| x.as_array()) {
                    let mut g = graph.write().expect("graph lock poisoned");
                    let mut added = 0;
                    for e in edges {
                        let from = e.get("from").and_then(|x| x.as_str()).unwrap_or("");
                        let to = e.get("to").and_then(|x| x.as_str()).unwrap_or("");
                        let sim = e.get("similarity").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        if from.is_empty() || to.is_empty() {
                            continue;
                        }
                        if g.add_edge(from, to, prokaryotes::GraphEdge::SemanticSimilar { similarity: sim }).is_some() {
                            added += 1;
                        }
                    }
                    let n = v.get("embeddings_count").and_then(|x| x.as_u64()).unwrap_or(0);
                    eprintln!("[semantic] {} embeddings | {} edges added", n, added);
                }
            }
            Err(e) => eprintln!("[semantic] compute failed: {}", e),
        }
    }

    let state = Arc::new(AppState {
        prokaryotes: Mutex::new(prokaryotes),
        storage: Mutex::new(storage),
        surface: surface.clone(),
        graph: graph.clone(),
        signal_tx: signal_tx.clone(),
        diff_tx: diff_tx.clone(),
        nvd_sidecar: nvd_sidecar.clone(),
        msrc_sidecar: msrc_sidecar.clone(),
        vault_sidecar,
        _semantic_sidecar: semantic_sidecar,
    });

    // Subscriber 1: surface state updater
    {
        let mut rx = signal_tx.subscribe();
        let surface = surface.clone();
        tokio::spawn(async move {
            while let Ok(signal) = rx.recv().await {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Ok(mut s) = surface.write() {
                    s.upsert(&signal, ts);
                }
            }
        });
    }

    // Subscriber 2: graph apply_signal + diff publish
    {
        let mut rx = signal_tx.subscribe();
        let graph = graph.clone();
        let diff_tx = diff_tx.clone();
        tokio::spawn(async move {
            while let Ok(signal) = rx.recv().await {
                let diff = match graph.write() {
                    Ok(mut g) => g.apply_signal(&signal),
                    Err(_) => continue,
                };
                if !diff.is_empty() {
                    let _ = diff_tx.send(diff);
                }
            }
        });
    }

    // Periodic NVD fetch
    {
        let sidecar = nvd_sidecar.clone();
        let tx = signal_tx.clone();
        let grace = Duration::from_secs(cfg.ingestion.nvd.periodic_grace_secs);
        let interval_d = Duration::from_secs(cfg.ingestion.nvd.periodic_interval_secs);
        let days_back = cfg.ingestion.nvd.periodic_days_back;
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            let mut interval = tokio::time::interval(interval_d);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                eprintln!("[periodic-nvd] tick (days_back={})", days_back);
                if let Err(e) = run_ingestion_fetch(
                    sidecar.clone(),
                    tx.clone(),
                    serde_json::json!({"cmd": "fetch_delta", "days_back": days_back}),
                    "nvd_ingestion",
                )
                .await
                {
                    eprintln!("[periodic-nvd] fetch error: {}", e);
                }
            }
        });
    }

    // Periodic MSRC fetch
    {
        let sidecar = msrc_sidecar.clone();
        let tx = signal_tx.clone();
        let grace = Duration::from_secs(cfg.ingestion.msrc.periodic_grace_secs);
        let interval_d = Duration::from_secs(cfg.ingestion.msrc.periodic_interval_secs);
        let months_back = cfg.ingestion.msrc.periodic_months_back;
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            let mut interval = tokio::time::interval(interval_d);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                eprintln!("[periodic-msrc] tick (months_back={})", months_back);
                if let Err(e) = run_ingestion_fetch(
                    sidecar.clone(),
                    tx.clone(),
                    serde_json::json!({"cmd": "fetch_delta", "months_back": months_back}),
                    "msrc_ingestion",
                )
                .await
                {
                    eprintln!("[periodic-msrc] fetch error: {}", e);
                }
            }
        });
    }

    // Router
    let app = Router::new()
        .route("/api/state", get(get_state))
        .route("/api/absorb", post(absorb_handler))
        .route("/api/surface", get(surface_handler))
        .route("/api/graph", get(graph_handler))
        .route("/api/ingest/nvd", post(ingest_nvd_handler))
        .route("/api/ingest/msrc", post(ingest_msrc_handler))
        .route("/api/vault_draft", post(vault_draft_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    eprintln!("[daemon] listening on http://{}", BIND_ADDR);
    axum::serve(listener, app).await?;

    Ok(())
}
