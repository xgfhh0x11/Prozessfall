import { useEffect, useRef, useState } from "react";
import Graph from "graphology";
import Sigma from "sigma";
import { NodeBorderProgram } from "@sigma/node-border";
import noverlap from "graphology-layout-noverlap";
import { marked } from "marked";
import {
  api,
  type GraphEdge,
  type GraphNode,
  type LayerSignal,
  type ProkaryotesState,
  type VaultDraft,
} from "./api";
import { DaemonSocket } from "./ws";
import "./App.css";

marked.setOptions({ gfm: true, breaks: true });

// Runtime CVSS threshold — changes with the filter sidebar slider.
const DEFAULT_CVSS_THRESHOLD = 9.0;
const CVSS_MIN = 7.0;
const CVSS_MAX = 10.0;
const CVSS_STEP = 0.1;

function nodeLabel(n: GraphNode): string {
  switch (n.kind) {
    case "cve":
      return n.id;
    case "cwe_cluster":
      return n.cwe ?? n.id;
    case "msrc_product":
      return n.product_tag ?? n.id;
    case "subsystem":
      return n.name ?? n.id;
    case "syntactic_invariant":
      return n.pattern ?? n.id;
    default:
      return n.id;
  }
}

function nodeSize(n: GraphNode): number {
  if (n.kind === "cve") {
    // More compact — CVSS 0 → 2.5px, CVSS 10 → 8px. It used to be 3-12; in the network view
    // large nodes covered the screen, keeping them small is closer to the BloodHound aesthetic.
    const cvss = n.cvss ?? 5;
    return 2.5 + (cvss / 10) * 5.5;
  }
  if (n.kind === "cwe_cluster") return 12;
  if (n.kind === "msrc_product") return 10;
  if (n.kind === "subsystem") return 9;
  if (n.kind === "syntactic_invariant") return 8;
  return 6;
}

// Linear interp from #3a3a40 (cool gray) → #e84545 (hot red).
// Burns when CVSS is high; blends into the background when low.
// Only the critical ones draw the eye — render noise drops.
function cvssGradient(cvss: number): string {
  const t = Math.min(Math.max(cvss / 10, 0), 1);
  const r = Math.round(0x3a + (0xe8 - 0x3a) * t);
  const g = Math.round(0x3a + (0x45 - 0x3a) * t);
  const b = Math.round(0x40 + (0x45 - 0x40) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function nodeColor(n: GraphNode): string {
  switch (n.kind) {
    case "cve":
      return cvssGradient(n.cvss ?? 0);
    case "cwe_cluster":
      return "#2D5A7B";
    case "msrc_product":
      return "#2D7B4A";
    case "subsystem":
      return "#7B2D7B";
    case "syntactic_invariant":
      return "#c4a545";
    default:
      return "#888";
  }
}

// Edge colors are very faint in ambient — they only glow on hover (boosted in the reducer).
function edgeColor(e: GraphEdge): string {
  switch (e.kind) {
    case "shares_cwe":
      return "#3a3a52"; // very faint blue-purple
    case "shares_product":
      return "#1f3a2a"; // very faint green
    case "semantic_similar":
      return "#2a4a6a"; // faint blue
    case "msrc_product":
      return "#1f3a2a"; // legacy
    default:
      return "#2a2a2a";
  }
}

// Hollow ring node: fill = bg (invisible), border = CVSS gradient.
// Even when overlapping, two rings appear separate — no blob effect.
const BG_COLOR = "#0a0a0c";

function addNodesToGraph(graph: Graph, nodes: GraphNode[]) {
  for (const n of nodes) {
    if (graph.hasNode(n.id)) continue;
    graph.addNode(n.id, {
      label: nodeLabel(n),
      size: nodeSize(n),
      color: BG_COLOR,
      borderColor: nodeColor(n),
      borderSize: 0.25,
      kind: n.kind,
      cvss: n.cvss ?? null,
      source: n.source ?? null,
      cwe: n.cwe ?? null,
      product_tag: n.product_tag ?? null,
      // x,y temporary — assignAttributeLayout computes them later
      x: 0,
      y: 0,
    });
  }
}

// Sunflower phyllotaxis layout — golden-angle (137.5°) spiral.
// Math guarantee: all N nodes get a unique position on the disc, equal angular distribution,
// sqrt(t) radial = equal node density per unit area. Typical FiveThirtyEight / NYT
// visualization pattern. Looks organic but is fully deterministic (same every run).
// Place in CVSS desc order → criticals near the center, less critical ones in the outer rings.
function assignSunflowerLayout(graph: Graph) {
  const phi = Math.PI * (3 - Math.sqrt(5)); // ~2.39996 rad = golden angle
  const sorted = [...graph.nodes()].sort((a, b) => {
    const ca = (graph.getNodeAttribute(a, "cvss") as number | null) ?? 0;
    const cb = (graph.getNodeAttribute(b, "cvss") as number | null) ?? 0;
    if (cb !== ca) return cb - ca; // critical first
    return a.localeCompare(b); // tie-break: id alphabetical
  });
  const n = sorted.length;
  const R = 300; // total disc radius (sigma camera auto-fits)
  sorted.forEach((node, i) => {
    const t = (i + 0.5) / n;
    const r = Math.sqrt(t) * R;
    const theta = i * phi;
    graph.setNodeAttribute(node, "x", r * Math.cos(theta));
    graph.setNodeAttribute(node, "y", r * Math.sin(theta));
  });
}

// Selection: the nearest MAX_SELECTION nodes within this many pixels of the click point
// land in the panel. The cap is critical — at low zoom the radius can cover the whole graph,
// and there's no point dumping 1000+ nodes into the panel.
const SELECTION_RADIUS_PX = 40;
const MAX_SELECTION = 15;

function addEdgesToGraph(graph: Graph, edges: GraphEdge[]) {
  for (const e of edges) {
    if (!graph.hasNode(e.from) || !graph.hasNode(e.to)) continue;
    if (graph.hasEdge(e.from, e.to)) continue;
    graph.addEdge(e.from, e.to, {
      size: 0.5,
      color: edgeColor(e),
      kind: e.kind,
    });
  }
}

function App() {
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const sigmaInstance = useRef<Sigma | null>(null);
  const graphInstance = useRef<Graph | null>(null);
  const hoveredNodeRef = useRef<string | null>(null);
  // CVSS threshold ref — the reducer reads this every frame. State is only for UI display.
  const cvssThresholdRef = useRef<number>(DEFAULT_CVSS_THRESHOLD);

  const [state, setState] = useState<ProkaryotesState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [signals, setSignals] = useState<LayerSignal[]>([]);
  const [fetchingNvd, setFetchingNvd] = useState(false);
  const [fetchingMsrc, setFetchingMsrc] = useState(false);
  const [graphInfo, setGraphInfo] = useState<string>("loading graph...");
  const [cvssThreshold, setCvssThreshold] = useState(DEFAULT_CVSS_THRESHOLD);
  const [wsState, setWsState] = useState<"connecting" | "open" | "closed">(
    "connecting",
  );
  // Selection panel — node ids near the click coordinates
  const [selection, setSelection] = useState<string[]>([]);
  // Vault draft state: which case the draft is loaded for, markdown content, loading flag
  const [draftFor, setDraftFor] = useState<string | null>(null);
  const [draftMarkdown, setDraftMarkdown] = useState<string>("");
  const [draftLoading, setDraftLoading] = useState(false);

  const decide = async (nodeId: string, outcome: number) => {
    try {
      await api.absorb(nodeId, outcome);
    } catch (e) {
      console.error("absorb failed:", e);
      setErr(String(e));
    }
  };

  const loadDraft = async (caseId: string) => {
    setDraftFor(caseId);
    setDraftLoading(true);
    setDraftMarkdown("");
    try {
      const resp: VaultDraft = await api.vaultDraft(caseId);
      if (resp.status === "ok" && resp.markdown) {
        setDraftMarkdown(resp.markdown);
      } else {
        setDraftMarkdown(
          `# Draft error\n\n\`\`\`\n${resp.error ?? "unknown"}\n${resp.traceback ?? ""}\n\`\`\``,
        );
      }
    } catch (e) {
      setDraftMarkdown(`# Draft fetch failed\n\n\`\`\`\n${String(e)}\n\`\`\``);
    } finally {
      setDraftLoading(false);
    }
  };

  const closeDraft = () => {
    setDraftFor(null);
    setDraftMarkdown("");
  };

  const updateGraphInfo = (g: Graph, threshold: number) => {
    let visible = 0;
    let total = 0;
    g.forEachNode((node) => {
      total++;
      const cvss = (g.getNodeAttribute(node, "cvss") as number | null) ?? 0;
      const kind = g.getNodeAttribute(node, "kind") as string;
      if (kind !== "cve" || cvss >= threshold) visible++;
    });
    setGraphInfo(
      `${visible} / ${total} nodes · cvss ≥ ${threshold.toFixed(1)}`,
    );
  };

  const handleCvssChange = (val: number) => {
    cvssThresholdRef.current = val;
    setCvssThreshold(val);
    if (graphInstance.current) updateGraphInfo(graphInstance.current, val);
    sigmaInstance.current?.refresh();
  };

  const refreshState = () => {
    api.state()
      .then(setState)
      .catch((e) => setErr(String(e)));
  };

  const triggerNvdFetch = async () => {
    setFetchingNvd(true);
    setErr(null);
    try {
      await api.ingestNvd(7);
    } catch (e) {
      setErr(String(e));
    } finally {
      setFetchingNvd(false);
    }
  };

  const triggerMsrcFetch = async () => {
    setFetchingMsrc(true);
    setErr(null);
    try {
      await api.ingestMsrc(3);
    } catch (e) {
      setErr(String(e));
    } finally {
      setFetchingMsrc(false);
    }
  };

  // ──────────────────────────────────────────────────────────────────
  // Sigma + graphology mount + initial graph load
  // ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!graphContainerRef.current) return;

    const graph = new Graph();
    let sigma: Sigma;
    try {
      sigma = new Sigma(graph, graphContainerRef.current, {
        renderLabels: true,
        labelFont: "ui-monospace, monospace",
        labelSize: 10,
        labelColor: { color: "#888" },
        labelDensity: 0.03,
        labelGridCellSize: 80,
        labelRenderedSizeThreshold: 9,
        labelWeight: "normal",
        defaultNodeColor: BG_COLOR,
        defaultEdgeColor: "#2a2a2a",
        minCameraRatio: 0.05,
        maxCameraRatio: 10,
        // Hollow ring rendering — modern aesthetic + overlap clarity
        defaultNodeType: "border",
        nodeProgramClasses: {
          border: NodeBorderProgram,
        },
        nodeReducer: (node, data) => {
          // Filter: hide CVEs below the CVSS threshold
          const cvss = (graph.getNodeAttribute(node, "cvss") as number | null) ?? 0;
          const kind = graph.getNodeAttribute(node, "kind") as string;
          if (kind === "cve" && cvss < cvssThresholdRef.current) {
            return { ...data, hidden: true };
          }
          // Hover dim/highlight
          const hovered = hoveredNodeRef.current;
          if (!hovered) return data;
          if (node === hovered) {
            return {
              ...data,
              size: data.size * 1.6,
              zIndex: 2,
              color: "#ffe8c2",
              borderColor: "#ffe8c2",
            };
          }
          const isNeighbor = graph.areNeighbors(hovered, node);
          if (isNeighbor) {
            return { ...data, zIndex: 1, borderSize: 0.35 };
          }
          return {
            ...data,
            borderColor: "#1f1f24",
            color: BG_COLOR,
            label: "",
            size: data.size * 0.75,
          };
        },
        edgeReducer: (edge, data) => {
          // Hide edges whose endpoints are caught by the filter
          const [from, to] = graph.extremities(edge);
          const fromCvss = (graph.getNodeAttribute(from, "cvss") as number | null) ?? 0;
          const toCvss = (graph.getNodeAttribute(to, "cvss") as number | null) ?? 0;
          const fromKind = graph.getNodeAttribute(from, "kind") as string;
          const toKind = graph.getNodeAttribute(to, "kind") as string;
          const fromHidden = fromKind === "cve" && fromCvss < cvssThresholdRef.current;
          const toHidden = toKind === "cve" && toCvss < cvssThresholdRef.current;
          if (fromHidden || toHidden) {
            return { ...data, hidden: true };
          }
          // Hover highlight
          const hovered = hoveredNodeRef.current;
          if (!hovered) return data;
          if (from === hovered || to === hovered) {
            return { ...data, color: "#ffb37d", size: data.size * 2.5, zIndex: 1 };
          }
          return { ...data, color: "#141416" };
        },
      });
    } catch (e) {
      setErr(`sigma init failed (WebGL?): ${e}`);
      setGraphInfo("sigma init failed");
      return;
    }

    sigmaInstance.current = sigma;
    graphInstance.current = graph;

    // Click logic: clickNode → take that node as anchor, within the radius in the viewport
    // list the NEAREST MAX_SELECTION nodes (sorted by distance, closest to the click
    // on top). clickStage → clear the selection.
    const findNearbyFromAnchor = (anchorVp: { x: number; y: number }) => {
      const r2 = SELECTION_RADIUS_PX * SELECTION_RADIUS_PX;
      const candidates: Array<{ node: string; dist: number }> = [];
      graph.forEachNode((node, attrs) => {
        const ax = (attrs as { x?: number }).x;
        const ay = (attrs as { y?: number }).y;
        if (typeof ax !== "number" || typeof ay !== "number") return;
        const vp = sigma.graphToViewport({ x: ax, y: ay });
        const dx = vp.x - anchorVp.x;
        const dy = vp.y - anchorVp.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < r2) candidates.push({ node, dist: Math.sqrt(d2) });
      });
      candidates.sort((a, b) => a.dist - b.dist);
      return candidates.slice(0, MAX_SELECTION).map((c) => c.node);
    };

    sigma.on("clickNode", ({ node }) => {
      const attrs = graph.getNodeAttributes(node) as { x?: number; y?: number };
      if (typeof attrs.x !== "number" || typeof attrs.y !== "number") {
        setSelection([node]);
        return;
      }
      const anchorVp = sigma.graphToViewport({ x: attrs.x, y: attrs.y });
      const nearby = findNearbyFromAnchor(anchorVp);
      setSelection(nearby.length > 0 ? nearby : [node]);
    });

    sigma.on("clickStage", () => {
      setSelection([]);
    });

    // Hover state — the reducer reads the ref; calling refresh re-runs all reducers.
    sigma.on("enterNode", ({ node }) => {
      hoveredNodeRef.current = node;
      sigma.refresh();
    });
    sigma.on("leaveNode", () => {
      hoveredNodeRef.current = null;
      sigma.refresh();
    });

    setTimeout(() => {
      setGraphInfo("fetching snapshot...");
      api.graph()
        .then((snapshot) => {
          setGraphInfo(`adding ${snapshot.nodes.length} nodes...`);
          setTimeout(() => {
            addNodesToGraph(graph, snapshot.nodes);
            addEdgesToGraph(graph, snapshot.edges);
            setGraphInfo(`layouting ${snapshot.nodes.length} nodes...`);
            setTimeout(() => {
              assignSunflowerLayout(graph);
              noverlap.assign(graph, {
                maxIterations: 30,
                settings: {
                  margin: 1,
                  expansion: 1.02,
                  ratio: 1.0,
                  speed: 3,
                },
              });
              sigma.refresh();
              updateGraphInfo(graph, cvssThresholdRef.current);
            }, 50);
          }, 50);
        })
        .catch((e) => {
          setErr(`graph load failed: ${e}`);
          setGraphInfo("graph load failed");
        });
    }, 200);

    return () => {
      sigma.kill();
      graph.clear();
    };
  }, []);

  // ──────────────────────────────────────────────────────────────────
  // WebSocket subscription — layer_signal + graph_diff
  // ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    refreshState();

    const sock = new DaemonSocket({
      onStateChange: setWsState,
      onLayerSignal: (s) => {
        setSignals((prev) => [s, ...prev].slice(0, 10));
        refreshState();
      },
      onGraphDiff: (diff) => {
        const graph = graphInstance.current;
        const sigma = sigmaInstance.current;
        if (!graph || !sigma) return;
        let mutated = false;
        for (const n of diff.added_nodes) {
          // Threshold is runtime now — add all nodes, the reducer decides what to hide.
          if (!graph.hasNode(n.id)) {
            graph.addNode(n.id, {
              label: nodeLabel(n),
              size: nodeSize(n),
              color: BG_COLOR,
              borderColor: nodeColor(n),
              borderSize: 0.25,
              kind: n.kind,
              cvss: n.cvss ?? null,
              source: n.source ?? null,
              // New nodes are outside the sunflower layout — random pos (re-layout via refresh is a separate job)
              x: (Math.random() - 0.5) * 300,
              y: (Math.random() - 0.5) * 300,
            });
            mutated = true;
          }
        }
        for (const n of diff.updated_nodes) {
          if (graph.hasNode(n.id)) {
            graph.setNodeAttribute(n.id, "size", nodeSize(n));
            mutated = true;
          }
        }
        for (const e of diff.added_edges) {
          if (
            graph.hasNode(e.from) &&
            graph.hasNode(e.to) &&
            !graph.hasEdge(e.from, e.to)
          ) {
            graph.addEdge(e.from, e.to, {
              size: 0.5,
              color: edgeColor(e),
              kind: e.kind,
            });
            mutated = true;
          }
        }
        if (mutated) sigma.refresh();
      },
    });
    sock.start();

    return () => sock.stop();
  }, []);

  return (
    <div className="app">
      <header className="status-bar">
        <span className="status-left">
          <strong>prozessfall</strong> · web ·{" "}
          <span className={`ws-state ws-${wsState}`}>{wsState}</span> ·{" "}
          {err ? (
            <span className="err">err: {err}</span>
          ) : state ? (
            <>
              decisions={state.decision_count} · coherence={state.coherence.toFixed(4)} ·
              epsilon={state.epsilon.toFixed(4)} · invariants={state.invariants} ·{" "}
              <span className="graph-info">{graphInfo}</span>
            </>
          ) : (
            "loading..."
          )}
        </span>
        <button className="action-btn" disabled={fetchingNvd} onClick={triggerNvdFetch}>
          {fetchingNvd ? "fetching nvd..." : "fetch nvd (7d)"}
        </button>
        <button className="action-btn" disabled={fetchingMsrc} onClick={triggerMsrcFetch}>
          {fetchingMsrc ? "fetching msrc..." : "fetch msrc (3mo)"}
        </button>
      </header>
      <div className="main">
        <aside className="filter-sidebar">
          <div className="filter-section">
            <div className="filter-label">cvss threshold</div>
            <div className="filter-value">≥ {cvssThreshold.toFixed(1)}</div>
            <input
              type="range"
              min={CVSS_MIN}
              max={CVSS_MAX}
              step={CVSS_STEP}
              value={cvssThreshold}
              onChange={(e) => handleCvssChange(Number(e.target.value))}
              className="filter-slider"
            />
            <div className="filter-scale">
              <span>{CVSS_MIN.toFixed(1)}</span>
              <span>{CVSS_MAX.toFixed(1)}</span>
            </div>
          </div>
          <div className="filter-section filter-hint">
            lower the slider → fewer critical nodes are shown (the outer rings
            of the sunflower spiral fill in). keep it high → criticals only.
          </div>
        </aside>
        <div ref={graphContainerRef} className="cy" />
        <aside className="sidebar">
          <div className="detail-panel">
            <div className="panel-header">
              selection {selection.length > 0 && <>· {selection.length}</>}
            </div>
            {selection.length === 0 ? (
              <div className="panel-empty">
                (click in graph — nodes within {SELECTION_RADIUS_PX}px are listed)
              </div>
            ) : (
              <div className="detail-list">
                {selection.map((nodeId) => {
                  const g = graphInstance.current;
                  if (!g || !g.hasNode(nodeId)) return null;
                  const attrs = g.getNodeAttributes(nodeId) as {
                    kind: string;
                    cvss?: number | null;
                    source?: string | null;
                    cwe?: string | null;
                    product_tag?: string | null;
                  };
                  return (
                    <div key={nodeId} className="detail-row">
                      <div className="detail-id">{nodeId}</div>
                      <div className="detail-meta">
                        <span className="detail-kind">{attrs.kind}</span>
                        {attrs.cvss !== null && attrs.cvss !== undefined && (
                          <span className="detail-cvss">
                            cvss {attrs.cvss.toFixed(1)}
                          </span>
                        )}
                        {attrs.source && (
                          <span className="detail-source">{attrs.source}</span>
                        )}
                        {attrs.cwe && (
                          <span className="detail-cwe">{attrs.cwe}</span>
                        )}
                        {attrs.product_tag && (
                          <span className="detail-product">{attrs.product_tag}</span>
                        )}
                      </div>
                      {attrs.kind === "cve" && (
                        <div className="detail-actions">
                          <button
                            className="act-opp"
                            onClick={() => decide(nodeId, 1)}
                          >
                            opp
                          </button>
                          <button
                            className="act-noise"
                            onClick={() => decide(nodeId, 0)}
                          >
                            noise
                          </button>
                          <button
                            className="act-draft"
                            onClick={() => loadDraft(nodeId)}
                          >
                            draft
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {draftFor && (
            <div className="draft-panel">
              <div className="panel-header">
                draft · {draftFor}
                <button className="panel-close" onClick={closeDraft}>
                  ✕
                </button>
              </div>
              {draftLoading ? (
                <div className="panel-empty">generating...</div>
              ) : (
                <div
                  className="draft-content"
                  dangerouslySetInnerHTML={{
                    __html: marked.parse(draftMarkdown) as string,
                  }}
                />
              )}
            </div>
          )}
          <div className="signal-feed">
            <div className="panel-header">recent signals</div>
            {signals.length === 0 ? (
              <div className="panel-empty">(no signals yet)</div>
            ) : (
              signals.map((s, i) => (
                <div key={i} className="signal-row">
                  <div className="case">{s.case_id}</div>
                  <div className="meta">
                    <span className="layer">{s.layer}</span>
                    <span className="source">{s.source}</span>
                    <span className={`delta ${s.delta >= 0 ? "pos" : "neg"}`}>
                      Δ{s.delta >= 0 ? "+" : ""}
                      {s.delta.toFixed(4)}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

export default App;
