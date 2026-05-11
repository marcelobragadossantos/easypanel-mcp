/**
 * OAuth 2.1 endpoint handlers.
 *
 * Implements:
 *   - RFC 8414  Authorization Server Metadata
 *   - RFC 9728  Protected Resource Metadata
 *   - RFC 7591  Dynamic Client Registration
 *   - RFC 7636  PKCE (S256 required)
 *   - authorization_code + refresh_token grants
 *
 * The /authorize endpoint serves a minimal HTML login page that accepts
 * Easypanel credentials. On successful login we bind the returned Easypanel
 * token to an opaque OAuth access token scoped to this MCP server.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { URL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { EasyPanelClient } from "../client.js";
import { OAuthStore, sha256Base64Url, type OAuthClient } from "./store.js";
import { CFAccessVerifier, extractCFToken } from "./cf-access.js";

export interface OAuthConfig {
  issuer: string;
  easypanelUrl: string;
  store: OAuthStore;
  /** Extra headers to send on backend calls to Easypanel (e.g. CF service tokens). */
  backendHeaders?: Record<string, string>;
  /** If set, /authorize POST enforces a valid CF Access JWT before accepting credentials. */
  cfAccessVerifier?: CFAccessVerifier;
  /** If true, submitted Easypanel email must equal the CF-authenticated email. */
  cfAccessRequireEmailMatch?: boolean;
}

type PendingAuthParams = {
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
};

export class OAuthHandler {
  constructor(private readonly cfg: OAuthConfig) {}

  /**
   * Returns true if the request was handled (including auth/errors).
   * Returns false if the path doesn't belong to the OAuth surface.
   */
  async handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url || "/", this.cfg.issuer);
    const pathname = url.pathname;

    // Serve both the base and path-aware well-known variants (RFC 9728 §3.1 / RFC 8414 §3.1).
    // MCP clients may request either form depending on which side constructs the URL.
    if (pathname === "/.well-known/oauth-authorization-server"
        || pathname === "/.well-known/oauth-authorization-server/mcp") {
      return this.serveAuthServerMetadata(res);
    }
    if (pathname === "/.well-known/oauth-protected-resource"
        || pathname === "/.well-known/oauth-protected-resource/mcp") {
      return this.serveProtectedResourceMetadata(res);
    }
    if (pathname === "/register" && req.method === "POST") {
      return this.handleRegister(req, res);
    }
    if (pathname === "/authorize" && req.method === "GET") {
      return this.handleAuthorizeGet(url, res);
    }
    if (pathname === "/authorize" && req.method === "POST") {
      return this.handleAuthorizePost(req, res);
    }
    if (pathname === "/token" && req.method === "POST") {
      return this.handleToken(req, res);
    }
    return false;
  }

  // ---- Metadata ----

  private serveAuthServerMetadata(res: ServerResponse): true {
    const issuer = this.cfg.issuer;
    json(res, 200, {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["mcp"],
    });
    return true;
  }

  private serveProtectedResourceMetadata(res: ServerResponse): true {
    const issuer = this.cfg.issuer;
    json(res, 200, {
      // MCP's OAuth profile wants the canonical resource URL to include the
      // protocol endpoint path, not just the origin.
      resource: `${issuer}/mcp`,
      authorization_servers: [issuer],
      scopes_supported: ["mcp"],
      bearer_methods_supported: ["header"],
    });
    return true;
  }

  // ---- Dynamic Client Registration ----

  private async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<true> {
    let body: any;
    try {
      body = await readJson(req);
    } catch {
      json(res, 400, { error: "invalid_client_metadata", error_description: "Body must be JSON" });
      return true;
    }

    const redirect_uris: unknown = body?.redirect_uris;
    if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      json(res, 400, {
        error: "invalid_redirect_uri",
        error_description: "redirect_uris must be a non-empty array",
      });
      return true;
    }

    for (const uri of redirect_uris) {
      if (typeof uri !== "string" || !isSafeRedirectUri(uri)) {
        json(res, 400, {
          error: "invalid_redirect_uri",
          error_description: `redirect_uri not allowed: ${uri}. Use https or http://localhost.`,
        });
        return true;
      }
    }

    const auth_method = body?.token_endpoint_auth_method === "client_secret_post"
      ? "client_secret_post"
      : "none";

    const client = this.cfg.store.registerClient({
      client_name: typeof body?.client_name === "string" ? body.client_name : undefined,
      redirect_uris: redirect_uris as string[],
      token_endpoint_auth_method: auth_method,
    });

    json(res, 201, {
      client_id: client.client_id,
      client_secret: client.client_secret,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
    return true;
  }

  // ---- Authorize (GET) - render login page ----

  private handleAuthorizeGet(url: URL, res: ServerResponse): true {
    const params = this.parseAuthorizeParams(url);
    if ("error" in params) {
      htmlError(res, 400, "Invalid request", params.error_description);
      return true;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
    });
    res.end(renderLoginPage(params, this.cfg.easypanelUrl));
    return true;
  }

  // ---- Authorize (POST) - accept credentials, issue code ----

  private async handleAuthorizePost(req: IncomingMessage, res: ServerResponse): Promise<true> {
    const form = await readForm(req);
    const params = this.parseAuthorizeParamsFromObject(form);
    if ("error" in params) {
      htmlError(res, 400, "Invalid request", params.error_description);
      return true;
    }

    const email = String(form.email || "").trim();
    const password = String(form.password || "");
    const totp = String(form.code || "").trim();

    if (!email || !password) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(renderLoginPage(params, this.cfg.easypanelUrl, "Email and password are required."));
      return true;
    }

    // Optional: enforce that the request actually came through CF Access.
    let cfEmail: string | null = null;
    if (this.cfg.cfAccessVerifier) {
      const token = extractCFToken(req);
      if (!token) {
        htmlError(res, 403, "Cloudflare Access required", "This deployment requires the login page to be reached through Cloudflare Access.");
        return true;
      }
      try {
        const claims = await this.cfg.cfAccessVerifier.verify(token);
        cfEmail = claims.email || null;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        htmlError(res, 403, "Cloudflare Access verification failed", msg);
        return true;
      }
      if (this.cfg.cfAccessRequireEmailMatch) {
        if (!cfEmail || cfEmail.toLowerCase() !== email.toLowerCase()) {
          res.writeHead(403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
          res.end(renderLoginPage(params, this.cfg.easypanelUrl,
            `Email must match your Cloudflare identity${cfEmail ? ` (${cfEmail})` : ""}.`));
          return true;
        }
      }
    }

    const client = this.cfg.store.getClient(params.client_id);
    if (!client || !client.redirect_uris.includes(params.redirect_uri)) {
      htmlError(res, 400, "Unknown client", "client_id or redirect_uri is not registered.");
      return true;
    }

    // Attempt login against Easypanel.
    const epClient = new EasyPanelClient(this.cfg.easypanelUrl, undefined, {
      extraHeaders: this.cfg.backendHeaders,
    });
    let token: string;
    try {
      const loginInput: Record<string, unknown> = { email, password };
      if (totp) loginInput.code = totp;
      const result: any = await epClient.mutation("auth.login", loginInput);
      token = result?.token;
      if (!token) throw new Error("Login returned no token");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.writeHead(401, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(renderLoginPage(params, this.cfg.easypanelUrl, `Login failed: ${msg}`));
      return true;
    }

    const code = this.cfg.store.createAuthCode({
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      code_challenge: params.code_challenge,
      code_challenge_method: "S256",
      scope: params.scope,
      easypanel_token: token,
      easypanel_url: this.cfg.easypanelUrl,
      user_email: email,
    });

    const redirect = new URL(params.redirect_uri);
    redirect.searchParams.set("code", code);
    if (params.state) redirect.searchParams.set("state", params.state);
    res.writeHead(302, { Location: redirect.toString(), "Cache-Control": "no-store" });
    res.end();
    return true;
  }

  // ---- Token ----

  private async handleToken(req: IncomingMessage, res: ServerResponse): Promise<true> {
    const form = await readForm(req);
    const grant = String(form.grant_type || "");

    if (grant === "authorization_code") {
      return this.handleTokenAuthCode(form, res);
    }
    if (grant === "refresh_token") {
      return this.handleTokenRefresh(form, res);
    }
    json(res, 400, { error: "unsupported_grant_type" });
    return true;
  }

  private handleTokenAuthCode(form: Record<string, string>, res: ServerResponse): true {
    const code = String(form.code || "");
    const code_verifier = String(form.code_verifier || "");
    const client_id = String(form.client_id || "");
    const redirect_uri = String(form.redirect_uri || "");
    const client_secret = form.client_secret ? String(form.client_secret) : undefined;

    if (!code || !code_verifier || !client_id || !redirect_uri) {
      json(res, 400, { error: "invalid_request", error_description: "Missing required parameters" });
      return true;
    }

    const client = this.cfg.store.getClient(client_id);
    if (!client) {
      json(res, 401, { error: "invalid_client" });
      return true;
    }

    if (client.token_endpoint_auth_method === "client_secret_post") {
      if (!client.client_secret || !client_secret || !constEq(client.client_secret, client_secret)) {
        json(res, 401, { error: "invalid_client" });
        return true;
      }
    }

    const entry = this.cfg.store.consumeAuthCode(code);
    if (!entry) {
      json(res, 400, { error: "invalid_grant", error_description: "Code expired or already used" });
      return true;
    }
    if (entry.client_id !== client_id || entry.redirect_uri !== redirect_uri) {
      json(res, 400, { error: "invalid_grant", error_description: "Client or redirect_uri mismatch" });
      return true;
    }

    const expected = sha256Base64Url(code_verifier);
    if (!constEq(expected, entry.code_challenge)) {
      json(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      return true;
    }

    const tokens = this.cfg.store.issueTokens({
      client_id,
      scope: entry.scope,
      easypanel_token: entry.easypanel_token,
      easypanel_url: entry.easypanel_url,
      user_email: entry.user_email,
    });
    json(res, 200, tokenResponse(tokens));
    return true;
  }

  private handleTokenRefresh(form: Record<string, string>, res: ServerResponse): true {
    const refresh_token = String(form.refresh_token || "");
    const client_id = String(form.client_id || "");
    const client_secret = form.client_secret ? String(form.client_secret) : undefined;

    if (!refresh_token || !client_id) {
      json(res, 400, { error: "invalid_request" });
      return true;
    }

    const client = this.cfg.store.getClient(client_id);
    if (!client) {
      json(res, 401, { error: "invalid_client" });
      return true;
    }
    if (client.token_endpoint_auth_method === "client_secret_post") {
      if (!client.client_secret || !client_secret || !constEq(client.client_secret, client_secret)) {
        json(res, 401, { error: "invalid_client" });
        return true;
      }
    }

    const rotated = this.cfg.store.rotateRefreshToken(refresh_token, client_id);
    if (!rotated) {
      json(res, 400, { error: "invalid_grant" });
      return true;
    }
    json(res, 200, tokenResponse(rotated));
    return true;
  }

  // ---- helpers ----

  private parseAuthorizeParams(url: URL): PendingAuthParams | { error: string; error_description: string } {
    const obj: Record<string, string> = {};
    url.searchParams.forEach((v, k) => { obj[k] = v; });
    return this.parseAuthorizeParamsFromObject(obj);
  }

  private parseAuthorizeParamsFromObject(obj: Record<string, string>): PendingAuthParams | { error: string; error_description: string } {
    const response_type = obj.response_type;
    const client_id = obj.client_id;
    const redirect_uri = obj.redirect_uri;
    const code_challenge = obj.code_challenge;
    const code_challenge_method = obj.code_challenge_method;

    if (response_type !== "code") {
      return { error: "unsupported_response_type", error_description: "response_type must be 'code'" };
    }
    if (!client_id) {
      return { error: "invalid_request", error_description: "client_id required" };
    }
    if (!redirect_uri) {
      return { error: "invalid_request", error_description: "redirect_uri required" };
    }
    if (!code_challenge || code_challenge_method !== "S256") {
      return { error: "invalid_request", error_description: "PKCE with S256 is required" };
    }

    const client = this.cfg.store.getClient(client_id);
    if (!client) {
      return { error: "invalid_client", error_description: "Unknown client_id" };
    }
    if (!client.redirect_uris.includes(redirect_uri)) {
      return { error: "invalid_request", error_description: "redirect_uri not registered for this client" };
    }

    return {
      client_id,
      redirect_uri,
      state: obj.state,
      code_challenge,
      code_challenge_method,
      scope: obj.scope,
    };
  }
}

// ---- low-level utilities ----

function tokenResponse(t: { access_token: string; refresh_token: string; scope?: string }) {
  return {
    access_token: t.access_token,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: t.refresh_token,
    scope: t.scope ?? "mcp",
  };
}

function isSafeRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1")) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function constEq(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 1024 * 64) req.destroy(); });
    req.on("end", () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

function readForm(req: IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 1024 * 64) req.destroy(); });
    req.on("end", () => {
      const ct = (req.headers["content-type"] || "").toLowerCase();
      if (ct.includes("application/json")) {
        try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
        return;
      }
      const out: Record<string, string> = {};
      const params = new URLSearchParams(data);
      params.forEach((v, k) => { out[k] = v; });
      resolve(out);
    });
    req.on("error", reject);
  });
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

function htmlError(res: ServerResponse, status: number, title: string, desc?: string): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(`<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;color:#222}h1{font-size:1.25rem}p{color:#555}</style>
<h1>${escapeHtml(title)}</h1>${desc ? `<p>${escapeHtml(desc)}</p>` : ""}`);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" } as Record<string, string>
  )[c]);
}

function renderLoginPage(params: PendingAuthParams, easypanelUrl: string, errorMsg?: string): string {
  const hidden = (name: string, value: string | undefined) =>
    value ? `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">` : "";
  const err = errorMsg
    ? `<div class="err">${escapeHtml(errorMsg)}</div>`
    : "";
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to EasyPanel MCP</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #f6f7f9; margin: 0; min-height: 100vh; display: grid; place-items: center; color: #1a1a1a; }
  @media (prefers-color-scheme: dark) { body { background: #0f1115; color: #e8e8e8; } .card { background: #171a20 !important; border-color: #2a2f38 !important; } input { background: #0f1115 !important; color: #e8e8e8 !important; border-color: #2a2f38 !important; } }
  .card { background: #fff; border: 1px solid #e2e5ea; border-radius: 12px; padding: 2rem; width: min(100%, 420px); box-shadow: 0 10px 30px rgba(0,0,0,0.06); }
  h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
  p.sub { margin: 0 0 1.25rem; color: #6b7280; font-size: 0.9rem; }
  label { display: block; font-size: 0.82rem; font-weight: 600; margin: 0.9rem 0 0.35rem; }
  input { width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #d1d5db; border-radius: 8px; font-size: 0.95rem; box-sizing: border-box; }
  button { margin-top: 1.25rem; width: 100%; padding: 0.65rem; border: 0; border-radius: 8px; background: #2563eb; color: #fff; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  .err { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; padding: 0.6rem 0.75rem; border-radius: 8px; font-size: 0.88rem; margin-bottom: 0.5rem; }
  .hint { margin-top: 1rem; font-size: 0.78rem; color: #6b7280; }
  code { background: rgba(127,127,127,0.15); padding: 0.1rem 0.3rem; border-radius: 4px; }
</style>
</head><body>
<form class="card" method="POST" action="/authorize" autocomplete="on">
  <h1>Sign in to EasyPanel</h1>
  <p class="sub">Authorizing access for an MCP client via <code>${escapeHtml(easypanelUrl)}</code>.</p>
  ${err}
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <label for="code">2FA code <span style="font-weight:400;color:#6b7280">(if enabled)</span></label>
  <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code">
  ${hidden("response_type", "code")}
  ${hidden("client_id", params.client_id)}
  ${hidden("redirect_uri", params.redirect_uri)}
  ${hidden("state", params.state)}
  ${hidden("code_challenge", params.code_challenge)}
  ${hidden("code_challenge_method", params.code_challenge_method)}
  ${hidden("scope", params.scope)}
  <button type="submit">Authorize</button>
  <p class="hint">Your credentials are sent to the Easypanel API and are not stored.</p>
</form>
</body></html>`;
}
