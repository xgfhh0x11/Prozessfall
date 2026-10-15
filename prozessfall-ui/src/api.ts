// Daemon REST client. Vite proxy /api/* → 127.0.0.1:8080.

export interface ProkaryotesState {
  coherence: number;
  epsilon: number;
  invariants: number;
  decision_count: number;
}

export interface LayerSignal {
  case_id: string;
  layer: string;
  source: string;
  delta: number;
}

export interface GraphNode {
  kind: string;
  id: string;
  cvss?: number | null;
  source?: string;
  cwe?: string;
  member_count?: number;
  product_tag?: string;
  cve_count?: number;
  name?: string;
  hit_count?: number;
  pattern?: string;
  negated_class?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: string;
  cwe?: string;
  similarity?: number;
  window_days?: number;
  evidence_count?: number;
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphDiff {
  added_nodes: GraphNode[];
  updated_nodes: GraphNode[];
  added_edges: GraphEdge[];
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path} ${res.status}: ${await res.text()}`);
  return res.json();
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} ${res.status}: ${await res.text()}`);
  return res.json();
}

export interface VaultDraft {
  status: string;
  case_id: string;
  mode?: string;
  markdown?: string;
  error?: string;
  traceback?: string;
}

export const api = {
  state: () => getJSON<ProkaryotesState>("/api/state"),
  graph: () => getJSON<GraphSnapshot>("/api/graph"),
  surface: (k: number) =>
    getJSON<unknown[]>(`/api/surface?k=${encodeURIComponent(k)}`),
  absorb: (deltaId: string, outcome: number) =>
    postJSON<LayerSignal>("/api/absorb", {
      delta_id: deltaId,
      outcome,
    }),
  ingestNvd: (daysBack: number) =>
    postJSON<unknown>("/api/ingest/nvd", { days_back: daysBack }),
  ingestMsrc: (monthsBack: number) =>
    postJSON<unknown>("/api/ingest/msrc", { months_back: monthsBack }),
  vaultDraft: (caseId: string, subsystem?: string) =>
    postJSON<VaultDraft>("/api/vault_draft", {
      case_id: caseId,
      subsystem,
    }),
};
