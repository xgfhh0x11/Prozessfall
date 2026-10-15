# Prozessfall — An Ambient Attack-Surface Graph Organ

> An in-progress research prototype: a persistent daemon that ingests real
> vulnerability data, builds an incrementally-updated graph of low-level
> attack surfaces, and exposes it as an interactive graph UI — meant to be
> *watched* like a radar rather than *queried* like a CLI tool.

**Status:** work in progress. `UnderstandingProzessfall.md` is the honest,
append-only build log that records every step and decision from phase 0
through phase 2.4 (daemon spine, event bus, data sidecars, SQLite→graph
projection, incremental graph updates, live web UI). This repository is a
snapshot of a prototype under active development, not a finished product.

---

## What it is

Prozessfall is the "ambient organ" evolution of
[Tiefenriss](https://github.com/xgfhh0x11/Tiefenriss), which built a *sealed
decision-intelligence core* for ranking the exploitability value of low-level
attack surfaces. Tiefenriss was, by design, a batch/CLI system. Prozessfall
asks a different question: **what if the same judgement ran continuously, as a
living surface a researcher glances at, instead of a command they invoke?**

The pivot that started this repo (recorded at the top of the build log) names
three things the CLI toolbox lacked and this prototype sets out to provide:

1. **A spine** — a continuously-running process, not an on-demand spawn.
2. **An event substrate** — components that share state through a common
   event bus rather than only indirectly through a database.
3. **An ambient surface** — a view you watch, not a report you pull.

## Architecture

```
  Python sidecars            Rust daemon (prokaryotes)         Web UI
  ────────────────           ─────────────────────────         ──────────────
  NVD / MSRC fetchers   ─▶    persistent AppState         ─▶    sigma.js graph
  semantic / structural      event bus + surface actor          (interactive,
  correlation                SQLite → graph projection           filter + vault
  vault draft generation     incremental graph diffs             preview panes)
```

- **`prokaryotes/`** — the Rust core: a persistent daemon (`src/bin/daemon.rs`)
  holding graph state (`graph.rs`, `graph_projection.rs`), layer/surface
  signals (`layer_signal.rs`, `surface.rs`), coherence/syntactic analysis, and
  a Python-sidecar supervisor (`python_sidecar.rs`). Serves the graph over a
  local HTTP endpoint.
- **Python sidecars** (repo root) — data acquisition and correlation:
  `nvd_fetcher.py` / `nvd_sidecar.py`, `msrc_sidecar.py`,
  `semantic_corellation.py`, `structural_corellation.py`, `surface_scanner.py`,
  `vault_sidecar.py`, `generate_vault_draft.py`.
- **`prozessfall-ui/`** — a Vite + TypeScript web app rendering the live graph
  with sigma.js, a CVSS filter slider, semantic edges, and a vault-draft
  preview pane.
- **`vault_examples/`** — worked example write-ups the vault pipeline produces
  (e.g. a ksmbd CWE-416 case, a Hyper-V CVE case).

## Running it (prototype)

The daemon and UI run as two local processes:

```
# Terminal 1 — the daemon (from prokaryotes/)
cargo run --bin daemon        # listens on http://127.0.0.1:8080

# Terminal 2 — the UI (from prozessfall-ui/)
npm install && npm run dev    # vite dev server on http://localhost:1420
```

Then open the UI in a browser. The daemon expects a Linux source checkout for
surface scanning and a local vulnerability database that the sidecars populate
from NVD/MSRC; neither the kernel checkout nor the generated `*.db` files are
committed to this repository (they are regenerable inputs, not source).

## Relationship to the wider work

Prozessfall shares its conceptual core with Tiefenriss and reuses the same
honest-engineering stance: the build log records what was tried, what was
decided, and where the design drifted, rather than presenting a clean
after-the-fact story. It is published as a prototype to show the working
method and the systems engineering, not as a shipped tool.

---

*A note on naming: some module and file names keep their original short names
from the author's working language (e.g. `cekirdek` = core, `veri` = data in the
sibling project). All prose, comments, and docstrings in this repository are in
English. `UnderstandingProzessfall.md` is the original running build log,
translated to English.*
