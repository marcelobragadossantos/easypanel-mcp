import http from "node:http";
import https from "node:https";

export interface EasyPanelClientOptions {
  /**
   * Invoked when the Easypanel API rejects a call as unauthenticated/forbidden
   * (HTTP 401/403 or tRPC code UNAUTHORIZED/FORBIDDEN). Fire-and-forget; used
   * by the OAuth layer to revoke the bound access+refresh token so the next
   * MCP call forces a re-login.
   */
  onAuthFailure?: () => void;
  /**
   * Extra headers to send on every request. Intended for things like
   * Cloudflare Access service tokens (CF-Access-Client-Id / CF-Access-Client-Secret)
   * so the shim can reach an Easypanel API that sits behind CF Zero Trust.
   */
  extraHeaders?: Record<string, string>;
}

export class EasyPanelClient {
  private baseUrl: string;
  private token: string | null = null;
  private onAuthFailure?: () => void;
  private extraHeaders: Record<string, string>;

  constructor(baseUrl: string, token?: string, opts?: EasyPanelClientOptions) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token ?? null;
    this.onAuthFailure = opts?.onAuthFailure;
    this.extraHeaders = opts?.extraHeaders ?? {};
  }

  async login(email: string, password: string): Promise<string> {
    const result = await this.mutation("auth.login", { email, password });
    this.token = result.token as string;
    return this.token;
  }

  async query(procedure: string, input?: Record<string, unknown>): Promise<unknown> {
    let url = `${this.baseUrl}/api/trpc/${procedure}`;
    if (input) {
      url += `?input=${encodeURIComponent(JSON.stringify({ json: input }))}`;
    }
    return this.request("GET", url);
  }

  async mutation(procedure: string, input: Record<string, unknown>): Promise<any> {
    const url = `${this.baseUrl}/api/trpc/${procedure}`;
    return this.request("POST", url, { json: input });
  }

  private fireAuthFailure(): void {
    if (!this.onAuthFailure) return;
    try { this.onAuthFailure(); } catch { /* swallow */ }
  }

  private request(method: string, url: string, body?: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = parsed.protocol === "https:" ? https : http;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...this.extraHeaders,
      };
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }
      const bodyStr = body ? JSON.stringify(body) : undefined;
      if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr).toString();

      const req = mod.request(parsed, { method, headers }, (res) => {
        const status = res.statusCode ?? 0;
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const httpAuthFailed = status === 401 || status === 403;
          try {
            const json = JSON.parse(data);
            const trpcCode =
              json?.error?.json?.data?.code ??
              json?.error?.data?.code ??
              json?.error?.code;
            const trpcAuthFailed = trpcCode === "UNAUTHORIZED" || trpcCode === "FORBIDDEN";
            if (httpAuthFailed || trpcAuthFailed) this.fireAuthFailure();

            if (json.error) {
              const msg = json.error?.json?.message ?? json.error?.message ?? JSON.stringify(json.error);
              reject(new Error(`tRPC error: ${msg}`));
            } else if (json.result?.data?.json !== undefined) {
              resolve(json.result.data.json);
            } else {
              resolve(json);
            }
          } catch {
            if (httpAuthFailed) this.fireAuthFailure();
            reject(new Error(`Invalid response: ${data.slice(0, 500)}`));
          }
        });
      });
      req.on("error", reject);
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }
}
