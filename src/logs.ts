/**
 * Container log streaming over Easypanel's `/ws/serviceLogs` WebSocket.
 *
 * Protocol (reverse-engineered from the panel UI bundle):
 *   wss://<host>/ws/serviceLogs?token=<EASYPANEL_TOKEN>&service=<docker-container-name>
 *                              [&compose=true&composeInternalService=<name>]
 *
 * Auth is the API token in the query string — `Authorization` header is not used.
 * Cookies are not required.
 *
 * Server sends text frames containing JSON: `{"output": "<chunk>"}`. Chunks may
 * carry partial lines, multiple lines, or ANSI escapes (the panel feeds them
 * straight into xterm.js).
 */

const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;

export interface ContainerLogsOptions {
  baseUrl: string;
  token: string;
  /** Docker container name. For project services this is `${projectName}_${serviceName}`. */
  service: string;
  compose?: boolean;
  composeInternalService?: string;
  /** Max lines to return — the most recent N (default 200). */
  tail?: number;
  /** Close after this many ms without new data (default 5000). */
  idleTimeoutMs?: number;
  /** Absolute cap on time spent waiting (default 30000). */
  hardTimeoutMs?: number;
  /** Strip ANSI color escapes (default true). */
  stripAnsi?: boolean;
}

export interface ContainerLogsResult {
  lines: string[];
  closedReason: "idle_timeout" | "hard_timeout" | "server_closed";
}

export async function getContainerLogs(opts: ContainerLogsOptions): Promise<ContainerLogsResult> {
  const tail = opts.tail ?? 200;
  const idleTimeoutMs = opts.idleTimeoutMs ?? 5000;
  const hardTimeoutMs = opts.hardTimeoutMs ?? 30000;
  const stripAnsi = opts.stripAnsi ?? true;

  const url = new URL(opts.baseUrl.replace(/\/+$/, "") + "/ws/serviceLogs");
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("token", opts.token);
  url.searchParams.set("service", opts.service);
  url.searchParams.set("compose", opts.compose ? "true" : "false");
  if (opts.composeInternalService) {
    url.searchParams.set("composeInternalService", opts.composeInternalService);
  }

  return new Promise<ContainerLogsResult>((resolve, reject) => {
    const WS = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    if (!WS) {
      reject(new Error("WebSocket not available — requires Node 22+ or a polyfill."));
      return;
    }

    const ws = new WS(url.toString());
    const lines: string[] = [];
    let buffer = "";
    let idleTimer: ReturnType<typeof setTimeout> | null = null;
    let hardTimer: ReturnType<typeof setTimeout> | null = null;
    let settled = false;

    const finish = (reason: ContainerLogsResult["closedReason"]) => {
      if (settled) return;
      settled = true;
      if (idleTimer) clearTimeout(idleTimer);
      if (hardTimer) clearTimeout(hardTimer);
      try { ws.close(); } catch { /* noop */ }
      // Flush any trailing partial line — it's the freshest output, so it must
      // survive the slice below even when we already hold `tail` complete lines.
      if (buffer.length > 0) {
        lines.push(stripAnsi ? buffer.replace(ANSI_RE, "") : buffer);
      }
      resolve({ lines: lines.slice(-tail), closedReason: reason });
    };

    const resetIdle = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => finish("idle_timeout"), idleTimeoutMs);
    };

    hardTimer = setTimeout(() => finish("hard_timeout"), hardTimeoutMs);

    ws.addEventListener("open", () => {
      resetIdle();
    });

    ws.addEventListener("message", (event: MessageEvent) => {
      const data = typeof event.data === "string" ? event.data : "";
      let chunk = "";
      try {
        const parsed = JSON.parse(data);
        if (typeof parsed?.output === "string") chunk = parsed.output;
        else return;
      } catch {
        return;
      }

      buffer += chunk;
      let nl = buffer.indexOf("\n");
      while (nl >= 0) {
        const raw = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        lines.push(stripAnsi ? raw.replace(ANSI_RE, "") : raw);
        // The WS replays history oldest->newest before going live. Keep only the
        // most recent `tail` lines (sliding window) and let idle/hard timeout
        // decide when we've caught up. Closing early on count returned the HEAD
        // of the backlog (stale) — the chronic "logs always behind" bug.
        if (lines.length > tail) {
          lines.shift();
        }
        nl = buffer.indexOf("\n");
      }

      resetIdle();
    });

    ws.addEventListener("close", () => finish("server_closed"));

    ws.addEventListener("error", (event: Event) => {
      if (settled) return;
      settled = true;
      if (idleTimer) clearTimeout(idleTimer);
      if (hardTimer) clearTimeout(hardTimer);
      const msg = (event as ErrorEvent).message || "WebSocket error";
      reject(new Error(`WebSocket error: ${msg}`));
    });
  });
}
