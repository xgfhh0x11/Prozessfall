# Understanding Prozessfall

Running log. Append-only, chronological. Every step lands here — like a .bashrc log.
Single doc: no spec, no todo, just what was done / decided.

---

## 2026-05-30 — Pivot session

`[diagnosis]` Prozessfall drift: it should have been an organ but turned into a CLI toolbox. Every TODO item was solved as a new `.py` + argparse flags; the net result produced a toolbox, not an ambient organ. The eagle is burdened with remembering commands / choosing flags — the spider work got pushed back onto them.

`[diagnosis]` Three structural gaps named:
  1. **No spine** — there is no continuously running process; Prokaryotes is not a daemon, it is spawned on-demand every time.
  2. **No event substrate** — the components don't speak a common language, they only touch indirectly through the DB; Prokaryotes is never informed, coherence/syntactic accumulation is disabled.
  3. **No ambient surface** — it doesn't watch like an eagle's radar, it pulls a report on command.

`[decision]` Movement: **toolbox → daemon-as-spine**. Approved.

`[decision]` We are not staying on the CLI. Interface: **BloodHound-style interactive graph UI**.

`[architecture]` Single Tauri application.
  - **Backend (Rust):** Prokaryotes core + ingestion + correlation + graph projection (`petgraph`) + in-process event bus + IPC handler.
  - **Frontend (React + Cytoscape.js):** force-directed graph, node coloring, click→side panel, filter sidebar, pathfinding.
  - **NLP:** Python sidecar (not PyO3 — iteration speed, lazy model load, Python-version independence).
  - **Storage:** SQLite as the single backend (the existing two-DB split becomes an internal table-level concern); graph in-memory `petgraph`, rebuilt from SQLite at startup, incrementally updated at runtime.
  - **Confidentiality:** single binary, no external port, uses Tauri IPC (Electron's localhost-port model rejected).

`[mapping]` BloodHound → Prozessfall reference language:
  - Neo4j → SQLite + petgraph
  - SharpHound collectors → NVD/MSRC fetchers (+ future Intel/Google/Qualcomm/ASML)
  - Principal/Computer/Group nodes → CVE / CWE cluster / MSRC product / subsystem / syntactic-invariant nodes
  - ACL edges → `semantic_similar` / `structural_cluster` / `temporal_spike` / `syntactic_negated` / `msrc_product` edges
  - "Shortest path to Domain Admin" → "shortest path from CVE to high-coherence invariant"
  - Electron → Tauri

`[scripts]` Fate of the existing scripts:
  - `surface_scanner.py` → `surface::scan()` internal module
  - `generate_vault_draft.py` → `vault::draft()` internal module
  - `nvd_fetcher.py` / `msrc_fetcher.py` → internal ingestion tasks supervised by the daemon
  - `prozessfall_bridge.py` → deleted (in-process, no need for a subprocess JSON bridge)
  - Top-level CLI surfaces are deleted in Phase 6. Prozessfall.app becomes the sole interface.

`[plan]` Phase plan:

| Phase | Duration | Deliverable | Done when |
|-----|------|-------------|-------|
| 0 — Foundation | 3 days | `config.toml`; Tauri scaffold; NLP sidecar/PyO3 decision; cytoscape decision | Empty Tauri window opens, Rust↔JS IPC channel works |
| 1 — Spine | 2 weeks | Prokaryotes persistent daemon mode; NVD/MSRC internal task; **LayerSignal output (old P1 #6)**; in-process event bus | Daemon ingests+absorbs in the background, queryable via IPC |
| 2 — Graph projection | 1 week | petgraph schema; SQLite→graph projection; incremental update; diff stream IPC | Daemon holds the graph in memory, streams diff events |
| 3 — MVP UI | 2 weeks | Cytoscape graph view; node coloring; click→side panel; live diff animation | The visual equivalent of `surface_scanner.py` |
| 4 — Decision loop + vault | 1 week | 0/1/skip side panel; verdict→Prokaryotes→graph update; live §0 vault draft render when a high-coherence node is selected | **USABLE THRESHOLD** — full eagle workflow |
| 5 — Filter + path + search | 2 weeks | Sidebar filters; search; pathfinding | BloodHound navigation parity |
| 6 — Cleanup | 1 week | Delete old CLI scripts; persist layout state; optional TUI fallback | No top-level executable |

`[constraint]` EXTp deadline 2026-08-19 (~12 weeks). Strategy: **stop at Phase 4**, defer Phase 5/6 to after EXTp. Phase 4 = ~6 weeks. If you start this week, a usable Prozessfall by mid-July, leaving August for EXTp.

`[cleanup]` Top-level Prozessfall docs deleted:
  - `prozessfall.md` (spec) — deleted
  - `prozessfall_todo.md` (TODO list) — deleted
  - `vault_entry_format.md` (vault format spec) — deleted
  
  Kept: `admin/*` (HBO motivation letter, HVA email, portfolio landing, etc.), `vault_examples/*` (demo writeups), all `.py` and Rust source. From now on this doc (`UnderstandingProzessfall.md`) is the single source of truth.

`[next]` Phase 0 startup steps, in order:
  1. `config.toml` — paths in a single place (old P0 #1), everything reads from it
  2. `npm create tauri-app` → `prozessfall-ui` scaffold; link the existing `prokaryotes` crate as the Rust backend
  3. Cytoscape.js + dummy 3-node graph render — end-to-end proof of the pipeline (do Tauri IPC + Cytoscape work?)
  4. NLP decision confirmation: sidecar (recommended) vs PyO3

---

## 2026-05-30 — Phase 0 / Step 1: config.toml + Python path wiring

`[done]` `config.toml` created, three paths in one place: `prozessfall_db`, `prokaryotes_db`, `prokaryotes_bin`. At the project root (`/home/tylersec/prozessfall/config.toml`).

`[done]` `prozessfall_config.py` loader written — reads TOML, exposes `PROZESSFALL_DB`/`PROKARYOTES_DB`/`PROKARYOTES_BIN` as `Path` objects. Python 3.10 fallback: `try tomllib (3.11+) / except: tomli`.

`[done]` 7 Python files moved to path wiring:
  - Top-level (simple import): `structural_corellation.py`, `semantic_corellation.py`, `nvd_fetcher.py`, `surface_scanner.py`, `generate_vault_draft.py` — in each one `DB_PATH = Path("...")` → `from prozessfall_config import PROZESSFALL_DB as DB_PATH`
  - Subdir (sys.path trick): `prokaryotes/msrc_fetcher.py` (BONUS: the relative-path bug `Path("prozessfall.db")` was fixed too — old P0 #2 closed here), `prokaryotes/prozessfall_bridge.py` (both `PROKARYOTES_BIN` and the `DB_PATH` in the `__main__` block switched to the import)

`[validation]` Worked:
```
cfg ok:
  prozessfall_db : /home/tylersec/prozessfall/prokaryotes/prozessfall.db | exists: True
  prokaryotes_db : /home/tylersec/prozessfall/prokaryotes/prokaryotes.db | exists: True
  prokaryotes_bin: /home/tylersec/prozessfall/prokaryotes/target/debug/prokaryotes | exists: True
ALL COMPILE OK
```
Both the `py_compile` syntax check and the runtime import test passed (top-level and subdir).

`[deferred]` The `const DB_PATH` inside Rust `main.rs` is left hardcoded. Reason: once we move to daemon mode in Phase 1, main.rs will be rewritten anyway, so touching it twice is pointless. The Rust side's config will be handled in Phase 1 when `toml` is added to Cargo deps.

`[gotcha]` Python 3.10 has no stdlib `tomllib` (3.11+), the `tomli` package is required. The loader works for both versions via try/except. `tomli` was already present on the system (v2.4.0).

`[delta]` 9 files changed, 3 new files: `config.toml`, `prozessfall_config.py`, log entry in `UnderstandingProzessfall.md`. Old P0 #1 and #2 closed.

`[next]` Phase 0 / Step 2: Tauri scaffold (`npm create tauri-app@latest -- --name prozessfall-ui --template react-ts`); link the existing `prokaryotes` crate to the Tauri Rust backend; dummy 3-node Cytoscape graph render. Awaiting approval — a prereq check (node/npm/rustc versions) before starting.

---

## 2026-05-30 — Phase 0 / Step 2: Tauri scaffold + prokaryotes link + dummy graph

`[prereq]` Empty starting point: rustc 1.93.1 + cargo 1.93.1 were present, everything else was missing.

`[install]` System deps + Node, a single `apt` + NodeSource sequence:
  - `libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `build-essential`, `pkg-config`
  - NodeSource Node 22 LTS → node v22.22.2, npm 10.9.7
  - WSL2 + WSLg present → GUI rendering will work (the Tauri window opens on the Windows host)
  - Passwordless sudo OK

`[scaffold]` `npx create-tauri-app@latest prozessfall-ui --template react-ts --manager npm --identifier com.tylersec.prozessfall`. Structure:
  - `prozessfall-ui/` (under the project root)
  - Frontend: Vite + React 19 + TypeScript, `src/App.tsx`, `src/App.css`
  - Backend: `src-tauri/` (Cargo 2021 edition, Tauri 2.11.2, lib.rs entry — Tauri 2 pattern, main.rs just calls `lib::run()`)

`[deps]` Frontend: `cytoscape` + `@types/cytoscape` added (74 packages total, 0 vulnerabilities). The react-cytoscapejs wrapper was not used — vanilla cytoscape + useRef/useEffect, for flexibility.

`[wiring]` Three integration points set up:

1. **Cargo.toml:** `prokaryotes = { path = "../../prokaryotes" }` added. The edition mismatch (prokaryotes=2024, ui=2021) is not an issue, cross-edition deps are supported in Rust.

2. **`src-tauri/src/lib.rs`:** Default `greet` command deleted. Replaced with a `prokaryotes_state` command:
   ```rust
   #[tauri::command]
   fn prokaryotes_state() -> ProkaryotesState {
       let p = Prokaryotes::new();
       ProkaryotesState {
           coherence: p.coherence.value(),
           epsilon: p.epsilon(),
           invariants: p.size(),
       }
   }
   ```
   Phase 0 dummy — creates a fresh Prokaryotes (will return coherence=1.0, epsilon=0.5, invariants=0). In Phase 1 it will be connected to the persistent daemon state.

3. **`src/App.tsx`:** Cytoscape mount + invoke. 3 dummy nodes (CVE-2026-31444 ksmbd, CWE-416 cluster diamond, CVE-2026-40402 Hyper-V), 3 edges (2× structural_cluster, 1× semantic_similar). A Prokaryotes state indicator (coherence/epsilon/invariants) via invoke in the top bar. COSE layout, dark theme, prep for the BloodHound aesthetic.

`[validation]` Both pipelines clean:
  - **Rust:** `cargo check` finished in 42s — `prokaryotes v0.1.0` and `prozessfall-ui v0.1.0` link OK, tauri 2.11.2 + webkit2gtk + tao + muda all compile.
  - **Frontend:** `npm run build` (vite production) finished in 1.12s — 32 modules transformed, 639KB JS bundle (cytoscape is large, gzip 204KB), TS types clean, no errors.

`[manual-verify]` Window launch was not tested in this session — `cd prozessfall-ui && npm run tauri dev` opens the Tauri dev window via WSLg. On first launch `src-tauri/target/debug/prozessfall-ui` is built (~1-2 min), then a hot-reload window via the Vite dev server + Tauri webview. Verify this manually — the graph should show 3 nodes, and the top bar should read `coherence=1.0000 · epsilon=0.5000 · invariants=0`.

`[gotcha-resolved]` On first launch the window stayed white — a WSLg + webkit2gtk compositing/GL bug (hardware acceleration blows up on WSLg). Fix: force software rendering with the `WEBKIT_DISABLE_COMPOSITING_MODE=1` env var. Made permanent: in `prozessfall-ui/package.json`, `"tauri": "tauri"` → `"tauri": "WEBKIT_DISABLE_COMPOSITING_MODE=1 tauri"`. After this, plain `npm run tauri dev` works; zero developer-recall burden. Note: Linux-only shell syntax — not portable to Windows (you can add `cross-env` if needed, unnecessary for now).

`[gotcha-resolved-2]` Second WSLg quirk: the window stuck to the top of the screen, the drag handle was unresponsive — dragging the title bar didn't move it. Two-layer fix:
  1. The `tauri.conf.json` window config was hardened: `width: 1400, height: 900, minWidth: 900, minHeight: 600, center: true, resizable: true, decorations: true`. The default 800×600 + no center → the window opened at coordinate (0,0) and fought with the WSLg compositor.
  2. `GDK_BACKEND=x11` env var — use XWayland instead of Wayland. WSLg's Wayland path sometimes fails to deliver webkit2gtk's drag/move events; the X11 path is old but deterministic.
  Made permanent: in `package.json`, `"tauri": "WEBKIT_DISABLE_COMPOSITING_MODE=1 GDK_BACKEND=x11 tauri"` (both env vars combined). After this, plain `npm run tauri dev` opens the correct window.

`[gotcha-resolved-3]` Third WSLg quirk: on maximize the aspect ratio broke, then the top-right close button became unresponsive. Pattern: GTK system decorations don't talk to the WSLg compositor reliably — going layer by layer with patches is not sustainable. **Structural fix: custom title bar + fully bypass maximize.**
  - `tauri.conf.json` → `decorations: false`, GTK chrome off
  - **First implementation (insufficient):** `data-tauri-drag-region` + three buttons (min/max/close) + `toggleMaximize()`. Problem: (a) in Tauri 2 the window APIs require explicit capability — with the permission missing, the buttons silently did nothing, (b) `data-tauri-drag-region` binds the default double-click to `toggleMaximize`, WSLg WM drops it into a half-tile and it can't be restored
  - **Correct implementation:**
    1. Window permissions added to `capabilities/default.json`: `core:window:default, allow-minimize, allow-close, allow-start-dragging`. Tauri 2 build-time capability check — silent fail if missing
    2. `data-tauri-drag-region` dropped, replaced with a custom `onMouseDown` handler — separates button clicks from drag via `e.target.closest('.tb-btn')`, calls `getCurrentWindow().startDragging()`. Double-click maximize isn't triggered because there's no drag-region attribute
    3. **Maximize button deleted.** We shouldn't expect the WSLg + GTK maximize path to get fixed — manual resize from the window edges already works (Tauri invisible resize handles), and the need for maximize isn't UX-critical. All we keep: minimize + close
  - The WEBKIT_DISABLE_COMPOSITING_MODE + GDK_BACKEND=x11 env vars are kept (still needed for the webview render + start_dragging path). All window interaction now goes through the Tauri JS API + the capability boundary, never reaching WSLg's decoration handlers.

`[validated-visually]` The window opened, 3 nodes + edges + top bar visible. Cytoscape render OK, Tauri IPC OK (the prokaryotes_state call returns), the prokaryotes crate is linked and working. **End-to-end pipeline proven.**

`[skipped]` Phase 0 / Step 4 (NLP sidecar vs PyO3 decision) requires no implementation — the sidecar decision was already made in the architecture. It will be validated in Phase 1 when the sidecar is written.

`[delta]` New directory: `prozessfall-ui/` (~250 npm packages + 250+ Rust crate target). 4 files changed: Cargo.toml (prokaryotes dep), lib.rs (prokaryotes_state), App.tsx (cytoscape dummy), App.css (dark theme fullscreen).

`[next]` Phase 1 — Spine. Prokaryotes persistent daemon mode. Concretely:
  1. Make `prokaryotes/src/main.rs` config-driven (the Rust leg of P0 #1 — add the `toml` crate to Cargo.toml)
  2. A **long-running process** instead of the subprocess JSON bridge + state queryable from Tauri via IPC. The existing `--json` bridge mode stays (legacy, for transition), a new `--daemon` mode is added.
  3. Port the NVD/MSRC fetchers into the daemon as internal tasks (or supervise them as Python sidecars) — the old Python scripts keep running in parallel until Phase 6.
  4. The **LayerSignal output format** (`[case_id | katman | kaynak | delta]`) is implemented — old P1 #6, now the canonical format in which the spine speaks to the outside world.
  5. In-process event bus (async channel) — ingestion events → correlation → Prokaryotes absorb → surface state update.

---

## 2026-05-30 — Phase 1.1: AppState + persistent Prokaryotes + LayerSignal type

`[architectural-choice]` Daemon = the Tauri Rust backend itself. There is NO separate `prozessfall-daemon` binary. When the window opens the daemon starts (loaded from the Prokaryotes DB), when the window closes the daemon dies. One window, one process, one state — a precise match for the spec's "single binary" promise. No need for a headless mode (single-user, no server).

`[prokaryotes-crate-extended]` New module in the `prokaryotes` core: `layer_signal.rs`. Inside it a `Layer` enum (`Makro/Mezo/Mikro/Lokal/Global` — the spec's abstraction levels) and a `LayerSignal { case_id, layer, source, delta }` struct. Re-exported from lib.rs. The type-level foundation of old P1 #6 is laid. There is no heuristic `classify_layer()` yet — it comes in Phase 1.4 when the ingestion paths are added.

`[mimari-karar]` The `Prokaryotes::absorb()` signature was **not changed** (still `-> ()`). The caller constructs the LayerSignal. Reason: layer classification is context-dependent (user_decision vs NVD ingestion vs MSRC ingestion sit in different layers); the Prokaryotes core shouldn't know this. LayerSignal is a value object — the type is defined in the core, but the instance is created at the integration boundary.

`[src-tauri-rewrite]` `prozessfall-ui/src-tauri/src/lib.rs` fully rewritten:
  - `AppState { prokaryotes: Mutex<Prokaryotes>, storage: Mutex<Storage> }` — managed as global app state via Tauri's `.manage()`.
  - **`Storage::restore_prokaryotes()` is called at startup** — all past decisions are replayed from `prokaryotes.db` and the in-memory state is restored. This now happens once per Tauri process (not on every script call, as before). The daemon is alive.
  - The `prokaryotes_state` command now takes a `State<AppState>` parameter — it reads from the **real persistent state**, not a fresh Prokaryotes. A `decision_count` field was added to the snapshot (for visual verification).
  - **New `absorb` command:** takes `(delta_id, outcome)` → coherence_before snapshot → `storage.save_decision()` (persist) → `prokaryotes.absorb()` (in-memory) → coherence_after snapshot → returns `LayerSignal { case_id, layer: Lokal, source: "user_decision", delta: after-before }`. All user decisions are in the Lokal layer for now; other layers open up once ingestion is added.
  - **Write order is storage-first**: Storage is authoritative — if the in-memory absorb ran first and then the storage save blew up, state would diverge. Now it's the reverse: DB first, then memory. (The current `Storage::save_decision` has a small chance of failing, but this is the correct order.)
  - DB path is still a hardcoded const — will be moved to config in Phase 1.2 (a TODO comment was left).

`[ui-tweak]` `App.tsx`: a `decisions={N}` field added to the status bar. The visual verification for Phase 1.1 — after a restart this number should not be 0 but the real decision count in the DB (around 14).

`[validation]` `cargo check` finished in 0.58s (incremental, only changed modules). No errors, no warnings. At the type level the whole IPC + Prokaryotes API is wired correctly.

`[manual-verify-needed]` Even if the dev server is running, **the Rust change does not arrive via hot-reload** — stop the `npm run tauri dev` process with Ctrl+C and restart it. Expected change: the top bar is NO LONGER `decisions=0 · coherence=1.0000 · epsilon=0.5000 · invariants=0` but the real DB state (around `decisions=14 · coherence=0.7530 · epsilon=0.5705 · invariants=13`). These numbers are the visual proof that Phase 1.1 works.

`[absorb-test-optional]` There is no button yet in the UI that triggers absorb (that's Phase 3 work). If you want, in the Tauri window open DevTools (right-click → Inspect) → Console:
```js
const { invoke } = window.__TAURI__.core;
await invoke('absorb', { deltaId: 'TEST-X', outcome: 1 });
// returns: { case_id: 'TEST-X', layer: 'lokal', source: 'user_decision', delta: ... }
```
If you run this, a new decision is written to the DB, and the next refresh shows `decisions=15`.

`[delta]` 3 files changed, 1 new: `prokaryotes/src/layer_signal.rs` (new), `prokaryotes/src/lib.rs` (mod + re-export), `prozessfall-ui/src-tauri/src/lib.rs` (full rewrite), `prozessfall-ui/src/App.tsx` (decision_count visible).

`[next]` Phase 1 sub-steps in order:
  - **1.2:** Event bus — `tokio::sync::broadcast` channel; producers (absorb, future ingestion tasks) publish, subscribers (Tauri frontend `emit`, surface state actor) listen. The UI now gets state changes via event subscription instead of IPC polling.
  - **1.3:** Surface state actor — holds a top-K opportunity list in memory, updated by events, queryable via a `surface_top_k` command. In Phase 3 the UI will render this.
  - **1.4:** NVD ingestion — the Rust-internal-task vs Python-sidecar decision kicks in now. Sidecar recommended; a stdio-loop wrapper is added to the existing `nvd_fetcher.py`, supervised by the daemon.
  - **1.5:** MSRC ingestion — same pattern.
  - **1.6:** Rust config — add the `toml` crate to `prokaryotes/Cargo.toml`, move the hardcoded DB path consts to reading config.toml.

---

## 2026-05-30 — Phase 1.2 + 1.3: Event bus + Surface state actor

`[scope]` I did both together because they're dependent: without the bus it's unclear how you'd feed the surface state; without the surface it's unclear what you'd test the bus with. Together they close a loop.

`[prokaryotes-crate-extended]` New module: `prokaryotes/src/surface.rs`. `SurfaceEntry { case_id, layer, source, delta, absorbed_count, last_updated_ts }` and `SurfaceState` (BTreeMap-backed, keyed by case_id). API: `upsert(&LayerSignal, ts)` and `top_k(k)` — descending order by |delta| magnitude. **Sync, no IO, no async** — a deliberate design rule: the core stays sync, async wrapping happens on the src-tauri side. Re-exported from lib.rs.

`[event-bus]` `tokio::sync::broadcast::channel::<LayerSignal>(256)` is part of AppState. Capacity 256 — on overflow, lagged subscribers lose old signals (broadcast semantics); the number can be raised for critical paths, sufficient for now. `tokio = { version = "1", features = ["sync"] }` added to Cargo.toml (only the sync feature — broadcast/mutex/rwlock is enough, the full runtime comes from tauri).

`[two-subscribers]` In Tauri's `.setup()` hook, two tokio tasks are spawned (`tauri::async_runtime::spawn`):

  1. **Surface state updater** — receives signals from the bus, upserts via `surface.write()`. Mutex/RwLock is std::sync (not parking_lot) because the critical section is small + has no await.

  2. **Frontend emitter** — receives signals from the bus, broadcasts to all webviews via `app_handle.emit("layer_signal", signal)`. The `tauri::Emitter` trait was imported. The frontend subscribes to this event via `listen<LayerSignal>("layer_signal", handler)`.

`[absorb-now-publishes]` The `absorb` command now also sends the `LayerSignal` it constructs to the bus (`signal_tx.send(signal.clone())`). The return value is the same signal (the caller can get it from both the direct response and the event stream). A bus-send error is silently swallowed — not critical if there's no receiver.

`[new-command]` `surface_top_k(k: usize) -> Vec<SurfaceEntry>` — the UI will call this in Phase 3. For now the signal-feed sidebar is fed by `listen` events (immediate update), with `surface_top_k` for cold-start or refresh.

`[ui-interactivity]` Three new behaviors in App.tsx:

  1. **Cytoscape node tap → absorb.** The tap handler calls `invoke('absorb', { deltaId: node.id(), outcome: 1 })`. Outcome=1 (Opportunity) is fixed; the 0/1/skip choice comes with a proper decision panel in Phase 4.

  2. **listen("layer_signal") subscription.** Prepends each incoming signal to the `signals` state (keep last 10), and also updates the prokaryotes_state counters via `refreshState()`. Reactive update — no IPC polling.

  3. **Signal feed sidebar.** A 280px panel on the right; shows case_id + layer + source + Δ (delta). Positive delta green, negative red. Empty state: "(tap a node to absorb)".

`[ui-css]` Layout `.app` flex-column → status bar on top + `.main` (flex-row: cy + signal-feed) below. Cytoscape `.cy` flex:1, sidebar fixed-width 280px. Dark theme kept, signal feed monospace + compact.

`[validation]` Both `cargo check` (0.31s incremental) and `npm run build` (1.05s, 32 modules, 641KB bundle) clean. One unused import warning (`Manager`) was caught and deleted.

`[manual-verify-needed]` Ctrl+C the `npm run tauri dev` → restart (Rust changed). Expected behavior:
  - Status bar: `decisions=14 · coherence=0.7530 · ...` (same as Phase 1.1, DB restore keeps working)
  - A new sidebar on the right: "RECENT SIGNALS" heading, with "(tap a node to absorb)" below it
  - Tap any graph node → the signal appears in the sidebar immediately (case_id + `lokal` + `user_decision` + `Δ+...`), the `decisions=` counter in the status bar increments by 1
  - Tap a few times → up to 10 signals stream; the counter keeps rising; the coherence value shifts slightly on each tap (persisted to DB + in-memory state in sync)

Visual proof: tap → bus publish → background task render → reactive UI update. The whole ring works.

`[design-note]` The surface state is currently filled only by user_decision signals — so it's not the "real surface" but "absorbed history". Once ingestion + correlation are added in Phase 1.4+, the surface will fill properly (ingestion event → correlation event → surface upsert → decided by the user). The current state of 1.3 is the **runtime proof** of the surface state machinery — the schema is correct, the lifecycle works, only the data sources are still single (the user's tap).

`[delta]` 1 new file (`prokaryotes/src/surface.rs`), 4 changes (`prokaryotes/src/lib.rs` re-export, `src-tauri/Cargo.toml` tokio dep, `src-tauri/src/lib.rs` event bus + setup hook + surface_top_k command, `App.tsx` tap handler + listen + sidebar, `App.css` layout + sidebar styling).

`[next]` Phase 1.4: NVD ingestion. The decision point — Rust internal task or Python sidecar.
  - **Sidecar (recommended):** a stdio-loop wrapper on the existing `nvd_fetcher.py`; the daemon supervises it, triggers/gets results via JSON-RPC. Existing code isn't rewritten, iteration speed is preserved.
  - **Rust port:** `reqwest` + `rusqlite` + JSON parse — straightforward but hours of work. Advantage: no Python supervise complexity, a cleaner single binary.
  Recommendation: sidecar. If you approve, in Phase 1.4 I'll add the `python_sidecar.rs` supervisor + a stdio loop to `nvd_fetcher.py`.

---

## 2026-05-30 — Phase 1.4a: NVD Python sidecar + supervisor + fetch trigger

`[approach]` The sidecar pattern was approved. The existing `nvd_fetcher.py` was not rewritten — an `nvd_sidecar.py` wrapper was placed next to it, calling the fetcher functions via stdio JSON-RPC.

`[python-sidecar]` `nvd_sidecar.py` (new, project root). Commands:
  - `{"cmd":"fetch_delta", "days_back":N}` → calls `fetch_nvd()`, returns count + a top-20 list of CVEs by CVSS
  - `{"cmd":"status"}` → DB summary (total_cves, last_fetch_at)
  - `{"cmd":"quit"}` → graceful exit

  **Critical rule — stdout is only for JSON-RPC.** `nvd_fetcher.fetch_nvd()` writes to stdout with `print()` (rate-limit progress, etc.). During fetch the sidecar redirects stdout to stderr (`stdout_to_stderr` contextmanager) — the JSON-RPC channel stays clean, and progress logs appear in the parent's terminal as stderr.

  Signal selection: after a fetch, from the DB, within the window, published >= cutoff CVSS DESC LIMIT 20 — the bus isn't spammed with 6000+ signals, only the most critical 20 are published.

`[rust-supervisor]` `prozessfall-ui/src-tauri/src/python_sidecar.rs` (new). `PythonSidecar` struct:
  - `spawn(label, python, script_path)` → start the child process, take the stdin/stdout pipe, wait for a **ready handshake** (the sidecar must write `{"status":"ready"}` at startup)
  - `call(cmd: Value) -> Value` → IO under a single Mutex (writing the request + reading the response is atomic, concurrent callers don't steal each other's responses)
  - `Drop` impl → first write a graceful `{"cmd":"quit"}`, then child.kill() + wait(). Leaves no orphan; on a daemon crash too, the Python script exits naturally on stdin EOF.
  - One IO mutex, a separate child mutex — no deadlock on drop.

`[lib-integration]` `src-tauri/src/lib.rs`:
  - `mod python_sidecar;` added
  - `AppState` → `nvd_sidecar: Arc<PythonSidecar>` field
  - the sidecar is spawned at the start of `run()` (before the Tauri builder starts — fail-fast: if the sidecar can't start, the daemon never opens)
  - New Tauri command: `trigger_nvd_fetch(days_back: u32)` → sidecar.call → publishes the CVE list in the response to the bus as `Layer::Mikro / source="nvd_ingestion" / delta=cvss/10.0` LayerSignals
  - The bus already feeds the surface state + emits to the frontend (Phase 1.2/1.3 architecture). NVD signals flow through the same channel as user_decision signals — a unified stream.

`[ui-button]` A "fetch nvd (7d)" button to the right of the status bar. Loading state ("fetching nvd..."), disabled while busy, hover styling. Default 7 days because the DB has been stale since May 24 — after this fetch the last week's CVEs come into the DB, and the top 20 are published to the bus.

`[smoke-test]` Standalone sidecar test:
```
$ (echo '{"cmd":"status"}'; sleep 0.2; echo '{"cmd":"quit"}') | python3 nvd_sidecar.py
{"status": "ready", "sidecar": "nvd"}
{"status": "ok", "total_cves": 6336, "last_fetch_at": null, "last_fetch_count": null}
{"status": "bye"}
```
Sequence: ready handshake → status (DB intact, 6336 CVEs) → graceful quit. The protocol works. `last_fetch_at` is null because the fetch_log table was just added (the existing DB comes from script-based fetches, where there was no log).

`[gotcha-fixed]` In the first smoke test `cmd_status` blew up because the `fetch_log` table was missing — `init_db()` was in `cmd_fetch_delta` but not in `cmd_status`. A defensive init_db call was added (idempotent CREATE IF NOT EXISTS, no-op when the tables exist).

`[validation]` `cargo check` 0.63s incremental clean, `npm run build` 1.12s clean. The standalone sidecar protocol proven.

`[manual-verify]` Restart `npm run tauri dev`. A new "fetch nvd (7d)" button to the right of the status bar. Click it:
  1. The button becomes "fetching nvd...", stays disabled
  2. stderr stream in the terminal: `[*] NVD fetch başlıyor: 2026-05-23... → 2026-05-30...`, then `[+] N/M CVE kaydedildi` (rate-limited 1s/page)
  3. When the fetch finishes, the top-20 highest-CVSS CVEs drop into the signal-feed sidebar — each one `Layer: mikro`, `Source: nvd_ingestion`, `Δ` = cvss/10
  4. The status bar `decisions` counter doesn't change (ingestion is not a decision), and coherence/epsilon stay the same too
  5. The button becomes active again

  If the bus has already been running since Phase 1.2/1.3, this time both user_decision (manual node tap) and nvd_ingestion signals flow mixed in a single feed — filtering for what matters to the eagle comes in Phase 5 (sidebar filters).

`[whats-not-done-yet]` What remains for Phase 1.4b:
  - **Periodic scheduling** — trigger_nvd_fetch runs automatically every N hours via `tokio::time::interval`. Currently manual button only.
  - **Sidecar crash detection + auto-restart** — `Drop` exists, but no runtime restart. If the sidecar crashes during a fetch, `call()` returns an error, the daemon keeps going but subsequent fetches also fail.
  - **Surface filtering** — right now NVD ingestion bursts 20 signals at once, the sidebar cuts at 10. The Phase 5 filter sidebar will discipline this.

`[delta]` 2 new files (`nvd_sidecar.py` project root, `prozessfall-ui/src-tauri/src/python_sidecar.rs`), 3 updates (`src-tauri/src/lib.rs` mod + AppState field + run() + trigger_nvd_fetch command, `App.tsx` button + loading state, `App.css` button styling + status-bar flex).

`[next]` Phase 1.5: MSRC sidecar — same pattern, `msrc_sidecar.py` + a second `PythonSidecar` instance. Then Phase 1.4b (periodic + auto-restart) and Phase 1.6 (Rust config). Which of these do you want to do first? My recommendation:
  1. **1.5 MSRC sidecar** (boring repetition, but the pattern is proven — 30 min of work)
  2. **1.4b periodic + auto-restart** (the transition from a manual button to an ambient organ — brings the spec's "it watches" sentence to life)
  3. **1.6 Rust config** (cleans up the hardcoded consts but opens no feature)

1.4b is the most strategic — without periodic fetch the daemon still runs on demand, the spec's ambient-observation sentence is not yet delivered.

---

## 2026-05-30 — Phase 1.4b: Periodic NVD fetch + sidecar auto-restart (ambient organ)

`[strategic-significance]` This step is strategic — here Prozessfall stops being a "request-response tool" and turns into an "ambient organ". The user opens the window and, even without clicking any button, the daemon starts watching NVD out in the world, signals flow. The first real runtime counterpart of the spec's "**it watches the opportunity space**" sentence.

`[sidecar-handle]` A second layer in `python_sidecar.rs`: `SidecarHandle`. Wraps PythonSidecar in an RwLock, stores the spawn config (label/python/script path).
  - if `call()` catches a pipe error (`closed stdout`, `Broken pipe`, `os error 32`) it calls `try_restart()`, then retries. The caller doesn't see the sidecar restart.
  - **10s cooldown** — a last_restart Instant is kept; the cooldown starts even on a spawn failure, preventing a restart storm.
  - During restart a write-lock is taken → in-flight calls complete, then a new inner is built. Newly arriving calls run with the new inner.
  - Under the write-lock, spawn either succeeds → cooldown set, replaces the inner; or fails → cooldown set, the error bubbles up (the daemon keeps going, retries after another 10s).

`[shared-helper]` `run_nvd_fetch(sidecar, signal_tx, days_back)` — called by both the `trigger_nvd_fetch` Tauri command and the periodic task. DRY + a single correct signal-publish code path.
  - via `tauri::async_runtime::spawn_blocking`, sidecar.call() doesn't hold the async runtime, it runs on a dedicated blocking thread.
  - The manual command is now an `async fn` — the frontend side already awaited a Promise, behavior unchanged.

`[periodic-task]` A third spawn in the `setup()` hook:
```
30s grace → tokio::time::interval(10dk) → loop:
  interval.tick().await
  run_nvd_fetch(..., days_back=1)
```
  - The 30s grace waits out the startup turbulence (window load + sidecar ready + Prokaryotes restore), so the first fetch starts smoothly.
  - A 10min interval is frequent enough to be visible in a dev session, gentle on the NVD API. The prod cadence (6h) becomes config-driven once moved to Phase 1.6 config.
  - `MissedTickBehavior::Skip` — prevents a burst after a laptop suspend.
  - days_back=1 (manual button 7) — periodic is incremental, querying only CVEs published yesterday. The top-20 query published to the bus is still `published >= cutoff` filtered, so if there's genuinely nothing new, nothing is added to the sidebar (no false signal).

`[design-note]` Periodic fires feed the surface state + the frontend signal feed through the same channel (the Phase 1.2 bus). In the sidebar, signals tagged `nvd_ingestion` flow mixed in with user_decision signals — filtering for what matters to the eagle comes in Phase 5 (sidebar filters). A mixed feed is accepted for now.

`[cargo-deps]` `tokio` features: `["sync"]` → `["sync", "time"]`. For `tokio::time::interval` and `sleep`.

`[validation]` `cargo check` 5.67s (tokio rebuilt for the new feature). No errors/warnings.

`[manual-verify]` Restart `npm run tauri dev`:
  1. The status bar shows normal Phase 1.x state
  2. **After 30 seconds** in the terminal stderr: `[periodic-nvd] tick (days_back=1)` → `[*] NVD fetch başlıyor: ...` → `[+] N CVE kaydedildi`
  3. The fetch finishes (if there are new CVEs) → `mikro · nvd_ingestion · Δ+...` signals drop automatically into the signal-feed sidebar. You clicked no button.
  4. **After 10 minutes** a second periodic fire — same pattern
  5. The manual "fetch nvd (7d)" button keeps working in parallel, doesn't collide with the periodic one (the sidecar Mutex serializes)
  6. If there are no new CVEs on the first periodic fire (the 1-day window is narrow), the sidebar may stay empty — seed it with the manual 7-day run, subsequent periodics catch the difference

`[restart-test-optional]` If you want to see auto-restart, find the sidecar PID from another terminal and `kill -9`:
```
ps aux | grep nvd_sidecar.py
kill -9 <pid>
```
On the next tick or a manual fetch trigger, you should see in stderr `[sidecar-handle] nvd pipe error, attempting restart: ...` → `[sidecar] nvd ready` → `[sidecar-handle] nvd restarted`. The fetch auto-retries and returns the result.

`[whats-not-yet]`
  - **Heartbeat indicator** — no visual cue in the UI for "daemon ingesting". It comes in the Phase 3 UI iteration as a small spinning dot or something like "last tick: 2m ago".
  - **Periodic schedule config** — 10min is hardcoded, becomes user-overridable once moved to Phase 1.6 Rust config.
  - **MSRC periodic** — once the Phase 1.5 MSRC sidecar lands, the same periodic pattern is applied to MSRC too.

`[delta]` 2 files updated: `Cargo.toml` (tokio time feature), `python_sidecar.rs` (SidecarHandle wrapper), `src-tauri/src/lib.rs` (shared helper + periodic task + AppState type).

`[next]` The remaining Phase 1 items, in order:
  - **1.5 MSRC sidecar** — `msrc_sidecar.py` + a second SidecarHandle. Pattern proven, 30 min of work. Once done, the daemon's ingestion side runs with two sources.
  - **1.6 Rust config** — add the `toml` crate to `prokaryotes/Cargo.toml`, move the hardcoded consts (PROKARYOTES_DB, NVD_SIDECAR_SCRIPT, PYTHON_BIN, periodic intervals) to config.toml. The Python side was already moved in Phase 0 Step 1; this step establishes symmetry on the Rust side.

Once these are done Phase 1 closes → Phase 2 (graph projection, petgraph schema) opens. 1.5 or 1.6 first? My recommendation is 1.5 — once MSRC ingestion is closed the ingestion layer is finished, a clean transition to Phase 2.

---

## 2026-05-30 — Phase 1.5: MSRC sidecar + ingestion helper generalization

`[python-side]` `msrc_sidecar.py` (new, project root). The MSRC adaptation of the NVD sidecar:
  - Command: `{"cmd": "fetch_delta", "months_back": N}` → the fetcher's `months_back` parameter
  - Signal query: `msrc_advisory WHERE bulletin_date >= cutoff ORDER BY cvss_score DESC LIMIT 20`
  - Puts an explicit `"source": "msrc_ingestion"` on each item — the Rust generic helper prioritizes the item-level source
  - Status: total_cves + exploitation_detected count
  - sys.path is both the project root and the `prokaryotes/` subdir (msrc_fetcher lives there)
  - Standalone smoke test: `{"status":"ready","sidecar":"msrc"}` → `{"total_cves":1865,"exploitation_detected":5}` → `bye`. Exactly matching the spec memory (1865 CVEs, 5 detected — the old script-based fetch still holds).

`[rust-side-refactor]` `run_nvd_fetch` → `run_ingestion_fetch` (generic). Signature:
```rust
async fn run_ingestion_fetch(
    sidecar: Arc<SidecarHandle>,
    signal_tx: broadcast::Sender<LayerSignal>,
    params: serde_json::Value,
    default_source: &'static str,
) -> Result<serde_json::Value, String>
```
The caller provides `params` (days_back/months_back/...) and a default source label. If each item has a `source` field it uses that, otherwise it falls back to the default. NVD and MSRC go through a single code path — DRY proven; adding a new vendor (Intel/Google) will be just a sidecar + spawn + periodic task, the helper is untouched.

`[lib-changes]`
  - `MSRC_SIDECAR_SCRIPT`, `PERIODIC_MSRC_GRACE` (60s, offset 30s from NVD), `PERIODIC_MSRC_MONTHS_BACK` (1) consts
  - `AppState.msrc_sidecar: Arc<SidecarHandle>` field
  - a second sidecar spawn at the start of `run()` — fail-fast: if the msrc sidecar doesn't start, the daemon never opens
  - New Tauri command: `trigger_msrc_fetch(months_back: u32)` → calls the generic helper
  - A second periodic task added to the setup hook — the same 10min interval as NVD, starting with a 30s offset
  - `trigger_msrc_fetch` added to the `invoke_handler` list

`[ui-button]` A second button next to the NVD button in the status bar: "fetch msrc (3mo)". Same loading state pattern (`fetchingMsrc`), same error handling. Default 3 months because MSRC bulletins are monthly — a 3-month seed covers the last quarter.

`[unified-feed]` The signal-feed sidebar now shows three signal types mixed:
  - `lokal · user_decision · Δ±...` (user node tap)
  - `mikro · nvd_ingestion · Δ+...` (NVD fetch, manual or periodic)
  - `mikro · msrc_ingestion · Δ+...` (MSRC fetch, manual or periodic)

Filtering in Phase 5. A mixed stream for now — the point of the proof: one bus, multiple sources.

`[validation]` `cargo check` 1.58s incremental clean. Standalone sidecar smoke passed.

`[manual-verify]` Restart `npm run tauri dev`:
  1. Status bar normal — two new buttons appear on the right ("fetch nvd (7d)", "fetch msrc (3mo)")
  2. **After 30s** terminal: `[periodic-nvd] tick (days_back=1)` — NVD fetch
  3. **After 60s** terminal: `[periodic-msrc] tick (months_back=1)` — MSRC fetch (30s after NVD)
  4. Both reflect into the signal-feed sidebar — different `source` tag by their origin
  5. After 10min both periodics fire again (NVD first, MSRC 30s later)
  6. The two manual buttons run in parallel — their fetching states are independent, the sidecars are separate processes

`[ingestion-layer-closed]` The daemon now ingests automatically from two vendors. The first two of the spec's "company feeds (Intel/Google/Qualcomm/CrowdStrike/ASML)" list — Microsoft (MSRC) and NIST (NVD) — are periodically active. Once others are added, the same pattern: `<vendor>_sidecar.py` + `SidecarHandle::spawn` + a periodic task. The helper is already generic.

`[delta]` 1 new file (`msrc_sidecar.py`), 2 updates (`src-tauri/src/lib.rs` MSRC integration + helper rename, `App.tsx` second button + state).

`[next]` Up next is Phase 1.6 — Rust config. The hardcoded consts (`PROKARYOTES_DB`, sidecar script paths, `PYTHON_BIN`, periodic intervals/grace/days_back) move to `config.toml`; the `toml` crate is added to `prozessfall-ui/src-tauri/Cargo.toml`. The Python side was already moved to config.toml in Phase 0 Step 1 — this step completes the symmetry. ~30 min of work, the closing of Phase 1.

After that, Phase 2 — Graph projection. petgraph schema, graph projection from SQLite, diff stream IPC. Phase 3 MVP UI (Cytoscape real graph) feeds from here.

---

## 2026-05-30 — Phase 1.6: Rust config — Phase 1 closure

`[config-schema]` `config.toml` extended (preserving the `[paths]` scalars the Python side reads, adding Rust-specific sections):
  - `[paths]` (existing) — scalars: prozessfall_db, prokaryotes_db, prokaryotes_bin
  - `[paths.sidecars]` (new) — nvd, msrc script paths
  - `[python]` (new) — bin (`python3`)
  - `[event_bus]` (new) — capacity
  - `[ingestion.nvd]` (new) — periodic_grace_secs, periodic_interval_secs, periodic_days_back
  - `[ingestion.msrc]` (new) — the same triple, months_back

The new sections didn't break the Python side — `prozessfall_config.py` only looks at flat keys like `_cfg["paths"]["prozessfall_db"]`, ignoring nested sections.

`[rust-config-module]` `prozessfall-ui/src-tauri/src/config.rs` (new):
  - `Config` struct hierarchy — serde Deserialize
  - **`Config::discover()`** — a two-stage search: first the `$PROZESSFALL_CONFIG` env override, then an upward search from the exe dir. In dev `target/debug/prozessfall-ui` → 5 levels up → finds config.toml at the project root. Production bundle paths differ, requiring a move to the Tauri app_data_dir in Phase 6+.
  - The Rust struct declares only the fields it uses — serde silently ignores unknown TOML keys (forward-compatible). `prozessfall_db` / `prokaryotes_bin` aren't in the Rust struct because Rust doesn't use them (Python does).

`[lib-changes]` The entire hardcoded const block removed from `lib.rs`:
  - `PROKARYOTES_DB`, `NVD_SIDECAR_SCRIPT`, `MSRC_SIDECAR_SCRIPT`, `PYTHON_BIN`, `EVENT_BUS_CAPACITY` — read from config
  - `PERIODIC_NVD_*`, `PERIODIC_MSRC_*` — read from config and wrapped with `Duration::from_secs`
  - at the start of `run()`, `let cfg = Config::discover().expect(...)` — fail-fast: if there's no config the daemon never opens
  - config values are moved into the periodic task closures — a new instance is needed for a runtime override (config is restart-only for now, hot-reload in Phase 6+)

`[cargo-deps]` `toml = "0.8"` added. serde + serde_json were already present.

`[validation]`
  - `cargo check` 0.56s incremental clean, the dead_code warning resolved
  - `Config::discover()` logs `[config] using /home/tylersec/prozessfall/config.toml` in stderr — transparent
  - Python config check: `prozessfall_config.PROZESSFALL_DB` gives the correct path, the new sections didn't get in the way

`[manual-verify]` `tauri dev` restart — behavior unchanged (config holds the same values), but now you can edit config.toml and change interval/grace via restart. Example: `[ingestion.nvd] periodic_interval_secs = 120` → NVD fires every 2 min. Or `$PROZESSFALL_CONFIG=/path/to/alt.toml npm run tauri dev` for a different profile.

`[delta]` 1 new file (`src-tauri/src/config.rs`), 3 updates (`config.toml` — new sections, `src-tauri/Cargo.toml` — toml dep, `src-tauri/src/lib.rs` — config-driven).

---

## Phase 1 closure summary

**The daemon spine is up.** After the scaffold + dummy graph was proven in Phase 0, over the course of Phase 1 we turned the toolbox into an ambient organ:

| Sub-phase | Deliverable | Done |
|---------|-------------|-------|
| 1.1 | AppState + persistent Prokaryotes from DB + LayerSignal type | ✓ |
| 1.2 | Event bus (tokio broadcast) + two subscribers (surface + frontend emit) | ✓ |
| 1.3 | SurfaceState actor + surface_top_k command | ✓ |
| 1.4a | NVD Python sidecar + supervisor + trigger command | ✓ |
| 1.4b | Periodic NVD + SidecarHandle auto-restart wrapper | ✓ |
| 1.5 | MSRC sidecar + ingestion_fetch helper generalization | ✓ |
| 1.6 | Rust config (shared config.toml) | ✓ |

**Right now, when you open the window:**
1. config.toml is loaded → Prokaryotes restored from DB → two sidecars spawned (NVD + MSRC ready handshake) → first periodic fetches fire at 30s and 60s
2. Automatic ingestion every 10 minutes (NVD + MSRC in sequence, 30s offset)
3. Cytoscape graph + signal-feed sidebar live
4. Manual: node tap → user_decision; "fetch nvd"/"fetch msrc" buttons → ingestion triggered
5. All signals flow from the bus → surface state + frontend emit, the eagle is continuously in the active field of view

**Alignment check against the spec:**
- "it **watches** the opportunity space" → the daemon ingests continuously ✓
- "layer marker" → the LayerSignal type is canonical, flowing from the bus ✓
- "it doesn't produce meaning, it only shows" → the sidebar feed is a neutral display, no commentary ✓
- Confidential → single binary, the sidecars are children of the Tauri process, no external port ✓
- "a skeleton that will build itself" → the spine exists, modular expansion: a new vendor = `<x>_sidecar.py` + `SidecarHandle::spawn` + periodic task ✓

**Was the spider burden really offloaded?** The eagle no longer has to remember any command. Open the window → signals flow. Manual intervention is optional (there are buttons for extra seeding, but the base case rests on zero action).

---

`[next]` **Phase 2 — Graph projection** opening. So far Cytoscape shows 3 dummy nodes; the real surface state must be built on petgraph and Cytoscape must feed from it. Sub-steps:

- **2.1:** A `graph.rs` module in the `prokaryotes` crate → petgraph schema. Node types: `CveNode`, `CweClusterNode`, `MsrcProductNode`, `SubsystemNode`, `SyntacticInvariantNode`. Edge types: `SemanticSimilar`, `StructuralCluster`, `TemporalSpike`, `MsrcProduct`, `SyntacticNegated`. Type definitions only, no IO.

- **2.2:** SQLite → graph projection. At daemon startup it reads from the `cve_raw` + `msrc_advisory` tables, builds an in-memory petgraph. A `graph: Arc<RwLock<ProzessGraph>>` field is added to AppState.

- **2.3:** Incremental update — a bus subscriber: when a new ingestion signal arrives, it adds a node/edge to the graph. Diff stream → emit to the UI via a Tauri event (new node arrived / edge added / weight changed).

- **2.4:** Tauri commands → `graph_snapshot()` full graph, `graph_subgraph(filters)` filtered subset. These are the endpoints the Phase 3 UI will consume.

`petgraph = "0.6"` is added to Cargo. Phase 2 is ~1 week solo, 2.1+2.2 can finish on the first day (data-shape decision + initial projection). If you approve, I'll start with 2.1.

---

## 2026-05-30 — Phase 2.1: Graph schema (petgraph + ProzessGraph wrapper)

`[scope]` Type definitions + basic API + unit tests only. No data population (2.2), no incremental update (2.3), no IPC expose (2.4). This step nails down the canonical graph shape — the next three sub-phases all ride on top of it.

`[dep]` `petgraph = "0.6"` added to `prokaryotes/Cargo.toml`. On the first download, fixedbitset + indexmap came in transitively, an edge-list-based `DiGraph` is used.

`[node-schema]` `GraphNode` — flat in JSON via `#[serde(tag = "kind", rename_all = "snake_case")]`:
  - `Cve { id, cvss, source }` — an individual CVE
  - `CweCluster { id, cwe, member_count }` — a cluster of CVEs with the same CWE (ID format: `cluster:CWE-416`)
  - `MsrcProduct { id, product_tag, cve_count }` — MSRC bulletin product grouping (`msrc_product:Hyper-V`)
  - `Subsystem { id, name, hit_count }` — Linux/Windows subsystem (`subsystem:ksmbd`)
  - `SyntacticInvariant { id, pattern, negated_class }` — a "definitely not Y" claim

  The `id()` helper extracts a stable string ID from the enum variant — petgraph's internal index stays hidden.

`[edge-schema]` `GraphEdge` — again `#[serde(tag = "kind")]`:
  - `SemanticSimilar { similarity }` — embedding similarity ≥ 0.8
  - `StructuralCluster { cwe }` — membership in the same CWE cluster
  - `TemporalSpike { window_days }` — a temporal-concentration signal
  - `MsrcProduct` — empty payload, just indicates membership
  - `SyntacticNegated { evidence_count }` — this pattern negates another

  Wire format: `GraphEdgeWire { from, to, #[serde(flatten)] data: GraphEdge }` — close to the `{ source, target, ...edge fields }` shape Cytoscape expects (the from→source rename on the frontend side is minor work).

`[graph-wrapper]` `ProzessGraph` — `DiGraph<GraphNode, GraphEdge>` + a `HashMap<String, NodeIndex>` reverse map:
  - **`upsert_node(node)`** — if called with the same id, the weight is overwritten, the NodeIndex is preserved → edges aren't broken, only the payload (cvss, count, etc.) is updated
  - **`add_edge(from_id, to_id, edge)`** — both endpoints must already be upserted, `None` if missing (caller responsibility)
  - **`snapshot()`** — returns a flat `GraphSnapshot { nodes, edges: Vec<GraphEdgeWire> }`, ready for IPC
  - `node_count`, `edge_count`, `contains(id)` helpers

  **The DiGraph (directed) choice** — the BloodHound analogy: attack-path edges are directed. For symmetric relations like SemanticSimilar an edge can be added in both directions, but the framework is directed → more general.

`[tests]` 4 unit tests, all passed (`cargo test --lib graph`):
  - `upsert_and_snapshot` — add node + edge, does snapshot count correctly
  - `upsert_updates_existing_preserves_index` — re-upsert with the same id → node count stays 1, weight updated
  - `add_edge_missing_endpoint_returns_none` — defensive API check
  - `edge_wire_serializes_flat` — JSON `{ from, to, kind, similarity }` flat shape

`[lib-export]` `prokaryotes/src/lib.rs` re-exports: `GraphEdge, GraphEdgeWire, GraphNode, GraphSnapshot, ProzessGraph`. The src-tauri cross-crate `use prokaryotes::ProzessGraph;` works (cargo check 4.27s clean).

`[validation]` Both the prokaryotes unit tests (4/4) and the src-tauri cargo check passed.

`[delta]` 1 new file (`prokaryotes/src/graph.rs`), 2 updates (`prokaryotes/Cargo.toml` petgraph dep, `prokaryotes/src/lib.rs` mod + re-export).

`[next]` Phase 2.2 — SQLite → graph projection. At daemon startup `cve_raw` + `msrc_advisory` are read, a `ProzessGraph` is built:
  - Each CVE → `GraphNode::Cve` (source field per the NVD/MSRC origin of the cvss)
  - CVEs with the same CWE → one `GraphNode::CweCluster` + a `GraphEdge::StructuralCluster` from each CVE to the cluster
  - Same MSRC product_tag → `GraphNode::MsrcProduct` + a `GraphEdge::MsrcProduct` from each CVE to the product
  - If the `cve_embeddings` table exists (the semantic-correlation Python side was writing it) → `GraphEdge::SemanticSimilar` for the top-K similarity

  A `graph: Arc<RwLock<ProzessGraph>>` field is added to AppState. The measurement is logged to see how many nodes/edges come out of ~6336 CVEs + ~1865 MSRC entries when the graph is built.

  Subsystem and syntactic_invariant nodes are skipped initially — these are derived signals, coming from bus events in Phase 2.3.

---

## 2026-05-30 — Phase 2.2: SQLite → graph projection (startup ingest)

`[db-check]` Before coding the projection I observed the real state of the DB:
  - `cve_raw`: 8423 (it was 6336 from memory — the periodic fetch is working, +2087)
  - `cve_embeddings`: 500 (only for the first 500 CVEs, the Python script produced it one-off)
  - `msrc_advisory`: 2152 (it was 1865 from memory, +287)
  - `fetch_log`: 8 (8 periodic fires recorded since Phase 1.6)
  - CWE distribution: the densest is CWE-79 (XSS, 541), CWE-416 (UAF, 277), CWE-89 (SQLi, 270), there are also compound CWEs (`["CWE-74","CWE-89"]`)
  - MSRC product: Mariner (a Linux distro) dominant with 1302, Edge 415, then smaller subsystems

`[scope-cut]` Semantic-similarity edges were **deferred to Phase 2.5**. Reason: parsing the `cve_embeddings` BLOB column format (sentence-transformers numpy float32 array serialization) on the Rust side + computing cosine sim is a separate task, not on the critical path of the projection. 2.2 was kept limited to a deterministic SQL-only projection.

`[projection-module]` `prokaryotes/src/graph_projection.rs` (new). `project_from_db(db_path) -> Result<ProzessGraph, String>`:
  1. **CVE nodes** — each row from `cve_raw` → `GraphNode::Cve { id, cvss, source }`. cwe_ids is JSON-parsed, and a cwe_counts map is accumulated in parallel.
  2. **CWE cluster nodes** — each unique CWE → `GraphNode::CweCluster { id: "cluster:CWE-X", cwe, member_count }`
  3. **StructuralCluster edges** — for each (CVE, CWE) pair a `CVE → cluster` edge
  4. **MSRC entries** — each row from `msrc_advisory`; if the CVE isn't in the graph, add it as MSRC-only (source: "MSRC"), accumulate product_tag
  5. **MSRC product nodes + edges** — each unique product → a `MsrcProduct` node + a `product → CVE` edge for each (product, CVE) pair

  Read-only connection (`SQLITE_OPEN_READ_ONLY`) — the projection doesn't modify the DB. The elapsed time of the entire projection is logged to stderr.

`[design-decision-first-write-wins]` If the same CVE exists in both NVD and MSRC: the node coming from NVD is kept (source="NVD"), the MSRC entry only adds a product-membership edge. Otherwise (re-upsert) the source info would be overwritten each time. Via the `graph.contains(&cve_id)` check, the MSRC side only adds the missing CVEs.

`[config-restore]` A `prozessfall_db` field was re-added to the `src-tauri/src/config.rs::Paths` struct (I dropped it in Phase 1.6 because Rust didn't use it, now it's needed for the projection).

`[lib-integration]`
  - `AppState` → `graph: Arc<RwLock<ProzessGraph>>` field
  - `project_from_db(&cfg.paths.prozessfall_db)` is called at startup inside `run()` — fail-fast: if the projection blows up, the daemon never opens
  - New Tauri command: `graph_snapshot() -> GraphSnapshot` — the UI still doesn't call it (that's Phase 2.4 work), but it can be invoked from devtools, the command is registered

`[validation]` `cargo check` 0.96s incremental clean. I didn't do a standalone smoke test — the projection logic will be logged to stderr on UI restart; if there's an error the daemon won't open (fail-fast). The code path is a single SQL select, deterministic.

`[manual-verify]` Restart `npm run tauri dev`:
  1. A new line in the terminal stderr: `[graph-projection] 8423 CVEs (N MSRC-only) | M CWE clusters | K MSRC products | structural=X msrc=Y | total nodes=... edges=... | ZZms` — the graph projection measurement
  2. The UI is unchanged — App.tsx still shows the dummy 3 nodes, the graph_snapshot command is for manual testing
  3. DevTools console:
     ```js
     const snap = await window.__TAURI__.core.invoke('graph_snapshot');
     console.log('nodes:', snap.nodes.length, 'edges:', snap.edges.length);
     console.log('sample node:', snap.nodes[0]);
     console.log('sample edge:', snap.edges[0]);
     ```
     Expected: ~8500 nodes (CVE + cluster + product), ~12-15k edges (structural + msrc). The sample node in the format `{ kind: "cve", id: "CVE-XXXX-XXXX", cvss: ..., source: "NVD" }`.

`[stress-prediction]` Simply dumping 8500 nodes + 12-15k edges into Cytoscape slows rendering (BloodHound CE gets visually dense at 2k+ nodes). That's why in the Phase 3 MVP UI the default view should be a top-K filter (e.g. cvss >= 7.5 or recent published). The full graph is always available on zoom-out, but the default view is narrowed.

`[delta]` 2 new files (`prokaryotes/src/graph_projection.rs`), 4 updates (`prokaryotes/src/lib.rs` mod + re-export, `src-tauri/src/config.rs` re-add prozessfall_db to Paths, `src-tauri/src/lib.rs` graph state + command + AppState field + invoke handler registration + imports).

---

## 2026-05-30 — Web pivot (Tauri shelved) + sigma.js + selection panel

`[strategic-pivot]` The WSLg + webkit2gtk pattern is clear: white window, drag bug, maximize bug, and Cytoscape zoom freezes due to software rendering. An env-var patch every time = unsustainable. **Full pivot to a web dashboard:** the browser on the Windows host gives full GPU + real DevTools + HMR; WSLg bypassed. The Tauri "single binary, no external port" confidentiality is gone — replaced by localhost-only HTTP+WS (port 8080). On a single-user machine there's no practical difference.

`[backend-axum-daemon]` A new `[[bin]]: daemon` (`src/bin/daemon.rs`) in the `prokaryotes` crate. The Tauri runtime was torn out entirely; an axum HTTP + WebSocket server. The existing AppState (Prokaryotes + Storage + Surface + ProzessGraph + two SidecarHandles + two broadcast channels) was wrapped in Arcs and passed to axum's State<Arc<AppState>>. The periodic tasks + subscribers (surface state updater, graph apply_signal+diff) use the same pattern via tokio::spawn. `python_sidecar.rs` and `config.rs` were moved from `src-tauri/` to `prokaryotes/src/`.

REST routes:
  - GET `/api/state` → ProkaryotesSnapshot
  - GET `/api/graph` → GraphSnapshot
  - GET `/api/surface?k=N` → top-K SurfaceEntry
  - POST `/api/absorb` body `{delta_id, outcome}` → LayerSignal
  - POST `/api/ingest/nvd` body `{days_back}` → fetcher response
  - POST `/api/ingest/msrc` body `{months_back}` → fetcher response

WebSocket `/ws`:
  - One connection per client, sigma broadcast: both `signal_tx` and `diff_tx` are subscribed
  - fan-out via tokio::select!, each event as a Text message with a `{type, payload}` JSON envelope
  - Client close → loop exit, clean daemon cleanup

Bind: `127.0.0.1:8080` (localhost only). Vite proxy `/api/*` and `/ws` → 8080 (the browser sees a single origin → no CORS).

`[frontend-helpers]` `src/api.ts` (typed fetch wrappers per endpoint) + `src/ws.ts` (auto-reconnect DaemonSocket, 1.5s retry, `connecting/open/closed` reflected to the UI via onStateChange). App.tsx fully rewritten: invoke→api.*, listen→DaemonSocket subscribers. The TAURI_AVAILABLE check + title bar + not-tauri fallback were **deleted**.

`[sigma-migration]` Cytoscape wasn't smooth on WSLg + software webkit (zoom 50s). Migration to sigma.js + graphology + ForceAtlas2 + noverlap. Sigma WebGL renderer — real GPU in the browser on the Windows host. **5-10x speedup**, 1000+ nodes smooth.

`[aesthetic-iterations]` Three refining passes:
  1. CVSS gradient: linear interp `#3a3a40` (cool gray) → `#e84545` (hot red). Only the critical ones burn, the rest blend into the background.
  2. Hover dim/highlight (BloodHound pattern): on hover a node turns white and grows, its neighbors normal, the rest fade to `#222226` + labels off + edges darken; the hovered one's edges turn orange. nodeReducer/edgeReducer + hoveredNodeRef.
  3. Hollow rings (`@sigma/node-border`): a hollow ring instead of a filled circle — when they overlap there's no blob, two separate circles read. Node overlap was additionally eliminated with ForceAtlas2 spread (scalingRatio 10→40, gravity 1→0.3, iterations 100→250) + noverlap post-process (margin 3, max iter 80).

`[relational-projection]` Hub-spoke (CweCluster/MsrcProduct super-nodes) → CVE-only + direct CVE↔CVE edges. New edge variants: `SharesCwe { cwe }`, `SharesProduct { product }`. Per cluster top-K=15 by CVSS, CVSS≥7 pre-filter (to control edge explosion). Direction: high CVSS → low (DiGraph). Result: 9427 CVE | 7198 shares_cwe + 850 shares_product = 8048 edges, 35ms projection.

`[selection-panel]` The tap-to-absorb behavior was deleted. New model: click the graph → the nearest 15 nodes within 40px of the click point drop into the selection panel (distance asc — nearest to the click on top). Each CVE row has `opp` + `noise` decision buttons. This both makes the nodes behind in a dense cluster reachable and fits the spec's "binary decision interface — decide by thinking" approach. The Phase 4 decision panel was delivered in this step.

Sidebar layout: detail-panel on top (current selection), signal-feed below (recent bus events) — a two-layer 320px panel.

`[cleanup-tauri]` `src-tauri/` deleted. The tauri deps (`@tauri-apps/api`, `@tauri-apps/plugin-opener`, `@tauri-apps/cli`) + cytoscape + script removed from `package.json`. The Tauri-specific parts of vite.config cleaned up. node_modules ~80MB.

`[gotcha-resolved-4]` The sigma clickStage event doesn't fire on a click over a node (sigma suppresses it), only clickNode fires. Both events must be bound. `getNodeDisplayData` in sigma 3 can give framed-graph space → reading graph attributes directly is reliable instead (`graph.getNodeAttribute(node, 'x')`).

`[run-workflow-current]`
```bash
# Terminal 1
cargo run --bin daemon
# → [config] using ... | [prokaryotes] restored ... | [graph-projection] relational ... | [daemon] listening on http://127.0.0.1:8080

# Terminal 2
cd prozessfall-ui && npm run dev
# → vite ready on http://localhost:1420

# Browser → localhost:1420 (Chrome/Edge/Firefox on Windows)
```

`[delta]` A structural migration within a single session: the Tauri layer was torn out entirely → daemon binary + axum router + WebSocket; Cytoscape torn out → sigma + graphology + node-border + noverlap; the UI rewritten from scratch (no Tauri imports, uses the api/ws helpers); aesthetic 3 iters (gradient + hover + rings); selection panel together with the decision UX. ~12 files changed or new: `prokaryotes/Cargo.toml` (axum/tokio/tower-http/futures/toml deps), `prokaryotes/src/lib.rs` (new mods), `prokaryotes/src/bin/daemon.rs` (new), `prokaryotes/src/python_sidecar.rs` (moved), `prokaryotes/src/config.rs` (moved), `prokaryotes/src/graph.rs` (new edge variants), `prokaryotes/src/graph_projection.rs` (relational rewrite), `prozessfall-ui/src/App.tsx` (rewritten from scratch), `prozessfall-ui/src/api.ts` (new), `prozessfall-ui/src/ws.ts` (new), `prozessfall-ui/src/App.css` (sidebar layout), `prozessfall-ui/vite.config.ts` (proxy), `prozessfall-ui/package.json` (deps fully revised), `prozessfall-ui/src-tauri/` (deleted).

`[next]` The web dashboard works, the decision UX works. There are three directions up next, and which to do first is strategic:

  - **A. Vault draft preview pane (remaining Phase 4):** When a high-coherence CVE is selected in the selection panel, the §0 Discovery Trace output of `generate_vault_draft.py` renders live below the panel. When a decision is made, the trace updates. **The real completer of the usable threshold** — the eagle now looks → decides → the draft is generated automatically.

  - **B. Filter sidebar (Phase 5):** CVSS slider, kind filter (cve/cwe_cluster/msrc on/off), source filter (NVD/MSRC), date range, search. Right now HIGH_CVSS_THRESHOLD is hardcoded to 9.0; without a runtime toggle the user can't flex the view. BloodHound parity starts here.

  - **C. Semantic edges (Phase 2.5):** cosine similarity from the `cve_embeddings` BLOBs → SemanticSimilar edges. The cross-CWE semantic bridges are a signal the spec specifically emphasizes. ~3-4 hours of work (BLOB format + cosine sim + bus integration).

  My recommendation: the order **A → C → B**. A completes the usable threshold (vault export = portfolio production). C opens the cross-CWE bridges, adding a new signal layer to the relational view (the semantic graph gets richer). B last — the filter sidebar is cosmetic relative to the other two features, can be added afterward.

---

## 2026-05-30 — A+B+C closure: vault preview + filter slider + semantic edges + layout evolution

**The final order ended up A → B → C** (B first because the CVSS slider is low effort, high value; it bumped semantic to later). Three sub-phases + additionally **layout evolution** (force-directed → bucket tracks → sunflower) and **selection panel iteration** (single-node tap → nearby query). Architectural decisions under each:

### Layout evolution — a structural journey

Three different paradigms tried in sequence, the final version is the third:

1. **ForceAtlas2 (since Phase 2.4)** — physics-driven force-directed. Problem: dense subgraphs clump into a ball (a star blob). Tuned to maximum spread with `scalingRatio` 40, `gravity` 0.3, still insufficient.

2. **Attribute bucket layout** — Y=CWE bucket, X=CVSS. Predictable but produced a "train track" pattern: 272 CWE buckets → 272 horizontal bands, each band squeezed into a narrow X-range by the CVSS filter. Worse than the blob.

3. **Sunflower phyllotaxis (final)** — a golden-angle (137.5°) spiral. Mathematically guaranteed: N nodes get a unique position on the disk, sqrt(t) radial = equal density per area, golden angle = all angular positions distinct. Sort: CVSS desc → the critical ones center, the less critical ones in outer rings. A typical FiveThirtyEight/NYT visualization pattern.

```typescript
function assignSunflowerLayout(graph: Graph) {
  const phi = Math.PI * (3 - Math.sqrt(5)); // ~137.5°
  const sorted = [...graph.nodes()].sort((a, b) => {
    const ca = (graph.getNodeAttribute(a, "cvss") as number | null) ?? 0;
    const cb = (graph.getNodeAttribute(b, "cvss") as number | null) ?? 0;
    if (cb !== ca) return cb - ca;
    return a.localeCompare(b); // deterministic tie-break
  });
  const R = 300;
  sorted.forEach((node, i) => {
    const t = (i + 0.5) / sorted.length;
    const r = Math.sqrt(t) * R;
    const theta = i * phi;
    graph.setNodeAttribute(node, "x", r * Math.cos(theta));
    graph.setNodeAttribute(node, "y", r * Math.sin(theta));
  });
}
```

**Lesson:** force-directed inherently produces dense clusters, attribute-bucket inherently produces an axis-aligned grid. The "orderly but organic" look in between comes from the phyllotaxis math — there's no physics force, but the organic distribution is algorithmically guaranteed.

### Selection panel — click disambiguation

The first implementation used a `clickStage` event handler. **Bug:** in sigma 3, clickStage fires only on a click in empty space; clicking over a node, `clickNode` suppresses clickStage. Both events must be bound.

Second bug: `getNodeDisplayData()` in sigma 3 can give framed-graph space → `graphToViewport` was doing a double-transform. Fix: reading graph attributes directly (deterministic):

```typescript
sigma.on("clickNode", ({ node }) => {
  const attrs = graph.getNodeAttributes(node) as { x?: number; y?: number };
  const anchorVp = sigma.graphToViewport({ x: attrs.x, y: attrs.y });
  const nearby = findNearbyFromAnchor(anchorVp);
  setSelection(nearby.length > 0 ? nearby : [node]);
});
```

Third iteration: on zoom-out a 30px radius covered the whole graph (1330-node selection). Fix: distance asc sort + top-K cap:

```typescript
const candidates: Array<{ node: string; dist: number }> = [];
graph.forEachNode((node, attrs) => {
  const vp = sigma.graphToViewport({ x: attrs.x, y: attrs.y });
  const d2 = (vp.x - anchorVp.x)**2 + (vp.y - anchorVp.y)**2;
  if (d2 < SELECTION_RADIUS_PX**2) candidates.push({ node, dist: Math.sqrt(d2) });
});
candidates.sort((a, b) => a.dist - b.dist);
return candidates.slice(0, MAX_SELECTION).map(c => c.node);  // top 15
```

UX decision: the tap-to-absorb behavior was removed entirely. New model: click → panel populates → the user consciously decides with the `opp` / `noise` button. It fits the spec's "binary decision interface — decide by thinking" approach; it also makes the nodes behind in a dense cluster reachable.

### A — Vault draft preview pane

**Design decision: sidecar pattern reuse.** `generate_vault_draft.py` existed (CLI). Instead of rewriting it, copy the NVD/MSRC sidecar pattern: a long-running Python process, JSON-RPC over stdio. The daemon spawns it, the REST endpoint `POST /api/vault_draft` passes the call to the sidecar.

**Alternative evaluated, rejected:** a one-shot subprocess per draft request. Fast but the python startup cost (~100ms) accumulates; long-running is more cost-efficient + the restart wrapper (SidecarHandle) already exists.

**Markdown render:** the `marked` npm package (~25KB gzip). The daemon returns a `markdown` string, the frontend turns it into HTML via `marked.parse(md)` → `dangerouslySetInnerHTML`. The backend is trusted (our own daemon) → no XSS risk.

**Layout: three-section sidebar.** detail-panel (selection, top), draft-panel (middle, visible only when draftFor is set), signal-feed (bottom). Toggle via a close button.

**Fallback bug fix (post-initial):** `generate_singleton_draft` requires the CVE to be in MSRC; NVD-only CVEs returned "ERROR". A fallback was added to the sidecar: if the singleton is ERROR, take the CVE's primary CWE from `cve_raw`, extract a subsystem keyword from the description (a curated 50-item list), fall back to cluster mode. A transparent "Fallback: ..." note in the header.

```python
if (case_id.startswith("CVE-")
    and "Discovery Trace — ERROR" in markdown
    and mode == "auto"):
    row = conn.execute(
        "SELECT cwe_ids, description FROM cve_raw WHERE cve_id = ?",
        (case_id,)
    ).fetchone()
    if row and row[0]:
        cwes = json.loads(row[0])
        if cwes:
            primary_cwe = cwes[0]
            inferred_subsys = extract_subsystem(row[1] or "")
            markdown = (
                f"> **Fallback:** {case_id} MSRC'de yok; "
                f"primary CWE `{primary_cwe}` ...\n\n"
                + generate_vault_draft(conn, primary_cwe, inferred_subsys, "cluster")
            )
```

Result: a draft is accessible for all 9457 CVEs (the 7000+ NVD-only ones via cluster fallback).

### B — Filter sidebar (CVSS slider)

**Design decision: reducer-based hide vs re-layout.** Two approaches:
- (a) Slider move → frontend filter → delete/add nodes from the graph → re-run sunflower → sigma.refresh. **Expensive** (~500ms-2s).
- (b) The whole graph stays loaded, slider move → the reducer returns `hidden: true` each frame → sigma optimizes it itself (skips hidden nodes). **Instant.**

(b) was chosen. Trade-off: all 9457 nodes are held in sigma's memory (~10MB). Hidden nodes leave a "gap" at their sunflower spiral positions, but since the order is CVSS desc, the hidden ones are in the outer rings — as the slider drops, the outer rings "fill". A meaningful visual.

**Closure trap solution:** the reducer is defined in the sigma constructor → it doesn't see React state changes (stale closure). Fix: a `useRef` for the threshold, the slider state updates both the ref and the React state, sigma.refresh() re-triggers the reducers.

```typescript
const cvssThresholdRef = useRef<number>(DEFAULT_CVSS_THRESHOLD);
const [cvssThreshold, setCvssThreshold] = useState(DEFAULT_CVSS_THRESHOLD);

const handleCvssChange = (val: number) => {
  cvssThresholdRef.current = val;      // reducer's read source
  setCvssThreshold(val);                // UI display
  updateGraphInfo(graphInstance.current!, val);
  sigmaInstance.current?.refresh();     // re-paint with new threshold
};

// In sigma constructor:
nodeReducer: (node, data) => {
  const cvss = graph.getNodeAttribute(node, "cvss") ?? 0;
  if (cvss < cvssThresholdRef.current) return { ...data, hidden: true };
  // ... hover logic
}
```

Edge reducer in parallel: if either endpoint is hidden the edge is hidden too.

**Initial graph load change:** previously the frontend filtered at fetch time via `applyDefaultFilter(snapshot)` — nodes not present on a slider dial-down weren't coming in. Now: all 9457 nodes are loaded, the reducer decides. Slider move = instant, no backend round-trip.

### C — Semantic edges

**BLOB format:** the `cve_embeddings.embedding` column was written with `np.float32 → tobytes()` (384-dim sentence-transformers all-MiniLM-L6-v2). Read: `np.frombuffer(blob, dtype=np.float32)`.

**Cosine similarity vector:** row-normalize then matrix product. For 500 embeddings, (500, 384) → normalize → `X @ X.T` = a (500, 500) sim matrix. Traverse the upper triangle, pairs above threshold ≥0.80 become an edge.

```python
emb = np.array([np.frombuffer(r[1], dtype=np.float32) for r in rows], dtype=np.float32)
norms = np.linalg.norm(emb, axis=1, keepdims=True)
norms[norms == 0] = 1.0
normalized = emb / norms
sim_matrix = normalized @ normalized.T  # (N, N) cosine sim
```

500 embeddings × 500 = 250k pair checks; numpy matrix mult ~milliseconds. Threshold 0.80 → 32 pairs (exactly the number memory predicted).

**Sidecar lifecycle: eager startup compute.** There were two options:
- (a) HTTP endpoint, lazy invoke (on-demand)
- (b) a one-off compute at daemon startup + inject into the graph

(b) was chosen because the `cve_embeddings` table is static (the Python script produced it one-off, no periodic regenerate). Eager compute = semantic edges ready on the UI's first open, no latency.

The sidecar is still kept alive (the `_semantic_sidecar` field, `_` prefix suppresses the unused warning) — it can be used later for lazy refresh / threshold change.

**Edge endpoint filtering:** an intersection problem between the 500 embedding CVEs and the 9457 graph CVEs. The embeddings were produced when the old Python script ran (the first 500 CVEs), the daemon's current graph is 9457 (grown via periodic fetch). `graph.add_edge()` requires both endpoints to exist → edges with a missing endpoint are silently skipped. All 32 pairs were added successfully (all of the old 500 are in the current graph).

### Comparison with the web pivot — why here?

These three sub-phases are also **a test of the web-pivot decision.** Had we stayed on Tauri:
- Vault draft: rendering marked in the WebView would work the same, but hot-reload is slow + WSLg webkit text rendering is glitchy
- CVSS slider: the ref+state pattern is the same, but due to the Tauri WSLg window refresh quirk the slider experience would be janky
- Semantic edges: graph modification + refresh — sigma WebGL would still freeze on WSLg software webkit under Tauri (the zoom problem wouldn't even let you notice the semantic edges)

In the browser it's all instant + smooth. **The web-pivot decision is validated.**

### Current system state (2026-05-30 EOD)

**Backend (Rust daemon, port 8080):**
- Prokaryotes core: 135 decisions, 51+ invariants, coherence 0.92+, persistent across restarts
- ProzessGraph: 9457 CVE nodes, ~8000 edges (shares_cwe 7198 + shares_product 850 + semantic_similar 32)
- 4 sidecars: NVD/MSRC (periodic, 10min interval), vault (on-demand + fallback), semantic (startup-once)
- Bus: 2 broadcast channels (signal_tx, diff_tx), 3 in-process subscribers + N WebSocket clients

**Frontend (browser, localhost:1420):**
- sigma WebGL + graphology
- Sunflower phyllotaxis layout (deterministic, 300px radius)
- Hollow rings (node-border program), CVSS gradient, dark theme
- Hover-based dim/highlight (neighbors brighten, the rest fade)
- Three-section right sidebar: selection / draft (lazy) / signal feed
- Left filter sidebar: CVSS slider runtime
- Status bar: ws state indicator, graph info, manual fetch buttons

**Line-by-line comparison against the spec:**
| Spec | Counterpart |
|------|----------|
| "it **watches** the opportunity space" | Periodic NVD + MSRC every 10min |
| "layer marker" output | LayerSignal canonical format, flowing over bus + WS |
| "it doesn't produce meaning, it only shows" | Neutral UI display, the decision is the user's |
| Binary decision interface | opp/noise per CVE, fed into Prokaryotes coherence |
| "definitely not Y" syntactic | The skeleton exists, SyntacticInvariant runtime signals still empty — Phase 3+ |
| Confidential | localhost-only, single-user machine, no external port |
| "a skeleton that will build itself" | The bus event system + sidecar pattern grow |
| Cross-CWE semantic bridges | 32 SemanticSimilar edges live (cyan dashed) |
| Vault entry §0 trace | Accessible for all CVEs via fallback |

**Gaps / next strategic decisions:**
- Source filter (NVD/MSRC toggle) — easy to add
- Edge kind filter (shares_cwe/product/semantic on/off) — easy
- Search box (CVE id) — medium
- Pathfinding ("CVE → nearest invariant") — BloodHound parity, medium-hard
- Decided node coloring (opp = green ring, noise = gray ring) — not done; persistent decision visual
- Hub view toggle (relational ↔ hub-spoke) — optional mode switch
- Company feeds (Intel/Google/Qualcomm/CrowdStrike/ASML) — the sidecar pattern is mechanical
- Syntactic invariant runtime signals (the spec's "definitely not Y" mechanism) — implemented in the Prokaryotes core but the production signal is still empty

`[next]` At this point the **tool is up + fed**. The strategic question: "build more features" vs "use the tool". The user's preference is the 3rd option (use), and that direction is more critical — it directly benefits the HBO portfolio, it can start producing CVE methodology traces. The build vs use decision is left to the next session.
  - `source = "nvd_ingestion"` or `"msrc_ingestion"` → CVE node upsert (the cvss field computed from the signal: delta*10)
  - New CVE → if there's no CWE link, skip for now (CWE info isn't in the signal — adding it to the sidecar is a Phase 2.3 sub-task)
  - user_decision signal → not reflected in the graph (only affects Prokaryotes coherence)
  - After each update a diff event ("graph_diff", payload: {added_nodes, added_edges, updated_nodes}) is emitted to the frontend → the UI will listen to it in Phase 3

  It will be added to the setup hook as subscriber 3. Same bus, a new consumer.

---

## 2026-05-30 — Phase 2.3: Incremental graph update + diff emit

`[graph-diff-type]` A `GraphDiff { added_nodes, updated_nodes, added_edges }` struct was added to `prokaryotes/src/graph.rs`. An `is_empty()` helper, to avoid emitting an empty diff. Serializable → can be emitted directly as a Tauri event payload.

`[apply-signal]` `ProzessGraph::apply_signal(&LayerSignal) -> GraphDiff` method:
  - if the `source` field isn't `nvd_ingestion` or `msrc_ingestion`, return an empty diff (user_decision doesn't change the graph)
  - take the CVE id from the signal, cvss = `signal.delta * 10.0` (the sidecar normalizes, multiply back), `.clamp(0.0, 10.0)` defensive
  - **Source preservation:** if the node already exists the old source is kept (first-write-wins) — if a CVE gets a signal first from NVD then from MSRC, the source stays "NVD", only the cvss is updated. Otherwise: the source flip-flops, the NVD/MSRC distinction the projection nails down breaks.
  - lands in `added_nodes` or `updated_nodes` depending on the existed flag

`[limitation-noted]` The signal carries no CWE info → when a new CVE arrives over the bus, the cluster link can't be established. Cluster edges come only from the startup projection. The longer the daemon lives, the more new CVEs accumulate as isolated nodes. Post-Phase 2.5: add a CWE field to the sidecar response (a simple Python change) → apply_signal can upsert the cluster + add the edge.

`[third-subscriber]` A third tokio task in the `src-tauri/src/lib.rs` setup hook:
  - Bus subscribe → `apply_signal()` under `graph.write()` for each signal
  - if the diff is non-empty, `app_handle.emit("graph_diff", diff)` → broadcast to all webviews
  - on mutex poisoning the loop continues (the diff computation is skipped, the next signal is tried)

`[tests]` 3 new unit tests (7 tests total, all passed):
  - `apply_signal_adds_new_cve_from_nvd` — new CVE, source="NVD", cvss=delta*10
  - `apply_signal_updates_existing_cve_preserves_source` — an MSRC signal to an existing NVD CVE → source stays NVD, cvss updated
  - `apply_signal_user_decision_no_graph_change` — a user_decision signal doesn't change the graph, the diff is empty

`[validation]` Both the prokaryotes tests (7/7) and the src-tauri cargo check (2.68s) clean.

`[manual-verify]` Restart `npm run tauri dev`:
  1. Normal projection log at startup (8500 nodes etc.)
  2. Set up a listener in the DevTools console:
     ```js
     await window.__TAURI__.event.listen('graph_diff', e => console.log('diff:', e.payload))
     ```
  3. Press the "fetch nvd (7d)" button (or wait 30s for the periodic one)
  4. In the console you should see a `{added_nodes: [...], updated_nodes: [...], added_edges: []}` payload for each CVE signal. Existing CVEs updated, new arrivals added.
  5. The sidebar feed shows the `layer_signal` events in parallel (since Phase 1.2). Two event streams in parallel: signal feed + graph diff. In Phase 2.4 the UI merges the two and updates Cytoscape live.

`[delta]` 2 files updated: `prokaryotes/src/graph.rs` (GraphDiff + apply_signal + 3 tests + LayerSignal import), `prokaryotes/src/lib.rs` (GraphDiff re-export), `src-tauri/src/lib.rs` (3rd subscriber + GraphDiff import).

`[next]` Phase 2.4 — UI integration. So far Cytoscape still shows 3 dummy nodes. In 2.4:
  1. At startup App.tsx loads all nodes/edges into Cytoscape via `invoke('graph_snapshot')`
  2. `listen('graph_diff', ...)` → incremental update via `cy.add(...)` / `cy.$('#id').data(...)` for each diff
  3. Node styling by kind: CVE = red circle (high cvss = brighter), CweCluster = blue diamond, MsrcProduct = green hexagon, Subsystem = purple square
  4. Performance: a COSE layout on 8500 nodes at once can be heavy — `cose-bilkent` or `fcose` is better for a large graph, alternatively `dagre` deterministic
  5. Stress mitigation: a high CVSS filter on the initial render (default cvss >= 7) or recent-only — then a "show all" toggle

  Phase 2.4 is bulkier than Phase 1.x in terms of size (Cytoscape config + styling + performance). 2-3 hours solo, fits in one session but a big chunk. If you approve, I'll start.

---

## 2026-05-30 — Phase 2.4: UI real graph data (the dummy 3-node era is over)

`[scope]` The Cytoscape layer of App.tsx was fully rewritten. No more dummy 3-node hardcoding; at startup the real graph is fetched from the daemon via `invoke('graph_snapshot')`, a default filter is applied and pushed to Cytoscape, `graph_diff` events do incremental updates.

`[default-filter]` 8500 nodes at once freeze the COSE layout. Default view:
  - **CVE nodes with `cvss >= 7.5`** (roughly 1000-2000 high-severity CVEs — the real number shows on restart)
  - **the CWE cluster + MSRC product nodes attached to them** (transitive closure 1 hop)
  - **all edges among these nodes**
  TS-side filter (`applyDefaultFilter`). A Rust-side filter alternative existed; TS is more flexible for UI iteration (the toggle is easy in Phase 5). The threshold is in the `HIGH_CVSS_THRESHOLD` const — a single line to change.

`[per-kind-styling]` A separate style for the five node kinds:
  - `cve` → red ellipse, **size by CVSS** (`mapData(cvss, 0, 10, 20, 55)`), label = CVE id (on the right)
  - `cwe_cluster` → blue diamond, label = CWE id (inside, bold), thick border
  - `msrc_product` → green hexagon, label = product_tag (wrap, max 60px)
  - `subsystem` → purple round-rectangle (will come from Phase 2.3+ runtime signals, placeholder)
  - `syntactic_invariant` → yellow triangle (Phase 2.3+ placeholder)

  Edge styles:
  - default → thin gray, opacity 0.35, `curve-style: haystack` (a fast straight line for a large graph)
  - `msrc_product` → green
  - `semantic_similar` → blue dashed bezier (embeddings coming in Phase 2.5)

  Selection ring: orange border on the clicked node.

`[interaction]` `cy.on('tap', 'node', ...)` now looks at the node kind — only `cve` nodes can be absorbed, cluster/product tap = no-op (in Phase 4 the side panel will open the CVE list belonging to that node).

`[incremental-updates]` A second useEffect: `listen('graph_diff', ...)`. For each diff:
  - `added_nodes` → `cy.add({ group: 'nodes', data })` for those passing the filter threshold
  - `updated_nodes` → in-place update via `cy.getElementById(id).data(...)` if present
  - `added_edges` → add the edge if both endpoints exist, skip if missing (edges are expected from the CVEs that filter out)

  Periodic NVD/MSRC fetch → each new high-CVSS CVE drops with a diff signal into both the signal-feed sidebar and the graph. The manual "fetch nvd" / "fetch msrc" buttons flow the same way.

`[layout]` COSE layout: `nodeRepulsion: 6000`, `idealEdgeLength: 60`, `fit: true`, `animate: false`. The first render can take a few seconds (a CPU-heavy layout pass). The `haystack` edge curve is much faster than bezier for a large graph.

`[ui-status]` A `graph-info` span added to the status bar: `X / Y nodes · K edges · cvss ≥ 7.5`. Blue-gray color, visually separate from the other state fields. Current: `decisions · coherence · epsilon · invariants · graph_info`.

`[refs]` `cyInstance` is kept as a useRef — so the diff listener can access the cytoscape instance after mount. The first useEffect sets the cy instance, the second useEffect writes to it by reference.

`[validation]` `npm run build` 1.12s clean, TS no errors. I didn't touch the Cargo side, the existing backend already emits diffs in Phase 2.3 — this step is pure frontend.

`[manual-verify]` `tauri dev` restart (a plain reload is no longer enough because of the full App.tsx rewrite + capabilities + tauri config change, a full restart is required):
  1. Title bar normal (the Phase 2.4 gotcha-3 fix)
  2. `loading graph...` appears in the status bar, then within 2-5 seconds `N / 8500 nodes · K edges · cvss ≥ 7.5`
  3. A real force-directed graph in the main area — red CVE nodes (size by CVSS), blue CWE diamonds, green MSRC hexagons
  4. Click a CVE → `lokal · user_decision · Δ+...` into the signal feed, the `decisions` counter in the status bar increments, coherence shifts
  5. "fetch nvd (7d)" → after 30-90s new high-CVSS CVEs should drop into both the signal feed and the graph (those passing the filter threshold)
  6. After 30s a periodic NVD tick fires, `[periodic-nvd] tick` in the terminal and a few seconds later the signal feed + graph update

  **If the COSE layout is too slow** (10s+ freeze): set `HIGH_CVSS_THRESHOLD = 8.5` or `9.0`, restart, try with fewer nodes. The threshold is a const at the top of App.tsx.

`[whats-not-yet]`
  - **Toggle filter UI** — HIGH_CVSS_THRESHOLD is a const for now, not changeable at runtime. In the Phase 5 filter sidebar: a threshold slider, kind filters (cve/cwe/msrc on/off), source filter (NVD/MSRC), date range.
  - **Side panel** — a detail panel when a node is selected (CVE description, CVSS vector, related CVEs, exploit status). Phase 4.
  - **Pathfinding** — "shortest path from X to invariant". Phase 5 (BloodHound parity).
  - **Semantic edges** — `cve_embeddings` BLOB parse + cosine sim. Phase 2.5.
  - **Diff handles missing endpoints** — if a new CVE comes over the bus but is outside the cluster filter, the edge can't be added. Acceptable, the user doesn't see it.

`[delta]` 2 files updated: `App.tsx` (full Cytoscape effect rewrite + 3 new type interfaces + filter/transform helpers + 2 new useEffects + status bar graph-info), `App.css` (.graph-info color).

`[next]` Phase 2 is largely done. Two remaining topics:
  - **2.5 — Semantic edges:** cosine similarity computation from the `cve_embeddings` BLOBs, `SemanticSimilar` edges. ~2-3 hours. Visually the most enriching addition (cross-CWE semantic bridges, a topic the spec emphasizes).
  - **Move to Phase 3:** decision loop UI improvement — right now it's single-click absorb=1, in Phase 4 a 0/1/skip side panel. **The Phase 5 filter sidebar** is the real BloodHound parity (filter + search + pathfinding).

  My recommendation: skip Phase 2.5 for now (semantic edges are nice-to-have but have a dependency — embedding regenerate may be needed, the scope grows), **go straight to Phase 3-4**: decision side panel + vault draft preview pane. This is the step that makes the "USABLE THRESHOLD". The UI is basically done now, but the eagle workflow (look → decide → vault draft) is missing. If you approve, let's do Phase 3-4 together.
