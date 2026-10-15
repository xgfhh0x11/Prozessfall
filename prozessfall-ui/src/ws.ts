// Daemon WebSocket client. Vite proxy /ws → ws://127.0.0.1:8080/ws.
// Auto-reconnect ile daemon down dönemini sessizce yutar.

import type { GraphDiff, LayerSignal } from "./api";

export type WsEvent =
  | { type: "layer_signal"; payload: LayerSignal }
  | { type: "graph_diff"; payload: GraphDiff };

type Handlers = {
  onLayerSignal?: (s: LayerSignal) => void;
  onGraphDiff?: (d: GraphDiff) => void;
  onStateChange?: (state: "connecting" | "open" | "closed") => void;
};

export class DaemonSocket {
  private ws: WebSocket | null = null;
  private reconnectTimer: number | null = null;
  private handlers: Handlers;
  private stopped = false;

  constructor(handlers: Handlers) {
    this.handlers = handlers;
  }

  start() {
    this.stopped = false;
    this.connect();
  }

  stop() {
    this.stopped = true;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
  }

  private connect() {
    this.handlers.onStateChange?.("connecting");
    const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.onopen = () => {
      this.handlers.onStateChange?.("open");
    };

    ws.onmessage = (e) => {
      try {
        const env = JSON.parse(e.data) as WsEvent;
        if (env.type === "layer_signal") this.handlers.onLayerSignal?.(env.payload);
        else if (env.type === "graph_diff") this.handlers.onGraphDiff?.(env.payload);
      } catch (err) {
        console.error("ws bad message:", err, e.data);
      }
    };

    ws.onclose = () => {
      this.handlers.onStateChange?.("closed");
      this.ws = null;
      if (!this.stopped) {
        this.reconnectTimer = window.setTimeout(() => this.connect(), 1500);
      }
    };

    ws.onerror = () => {
      // close handler does the reconnect; nothing to do here
    };
  }
}
