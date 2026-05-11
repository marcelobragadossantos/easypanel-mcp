/**
 * OAuth 2.1 storage: clients, authorization codes, access/refresh tokens.
 *
 * Persists to a JSON file so tokens survive restarts. In-memory cache is
 * the source of truth; disk is a write-through backup.
 *
 * This is a single-tenant-ish store: small deployments only. If you ever
 * need horizontal scaling, swap this for Redis.
 */

import { randomBytes, createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export interface OAuthClient {
  client_id: string;
  client_secret?: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: "none" | "client_secret_post" | "client_secret_basic";
  created_at: number;
}

export interface AuthCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256";
  scope?: string;
  easypanel_token: string;
  easypanel_url: string;
  user_email: string;
  expires_at: number;
}

export interface AccessToken {
  access_token: string;
  refresh_token: string;
  client_id: string;
  scope?: string;
  easypanel_token: string;
  easypanel_url: string;
  user_email: string;
  expires_at: number;
}

interface StoreData {
  clients: Record<string, OAuthClient>;
  codes: Record<string, AuthCode>;
  tokens: Record<string, AccessToken>;
  refresh_index: Record<string, string>;
}

const CODE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TTL_MS = 60 * 60 * 1000;

export class OAuthStore {
  private data: StoreData = { clients: {}, codes: {}, tokens: {}, refresh_index: {} };
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(private readonly storePath: string) {}

  async load(): Promise<void> {
    try {
      const raw = await fs.readFile(this.storePath, "utf8");
      this.data = JSON.parse(raw);
      if (!this.data.clients) this.data.clients = {};
      if (!this.data.codes) this.data.codes = {};
      if (!this.data.tokens) this.data.tokens = {};
      if (!this.data.refresh_index) this.data.refresh_index = {};
    } catch (e: any) {
      if (e.code !== "ENOENT") throw e;
    }
    this.sweep();
  }

  private persist(): void {
    const snapshot = JSON.stringify(this.data);
    this.writeQueue = this.writeQueue
      .then(async () => {
        await fs.mkdir(path.dirname(this.storePath), { recursive: true });
        const tmp = `${this.storePath}.tmp`;
        await fs.writeFile(tmp, snapshot, { mode: 0o600 });
        await fs.rename(tmp, this.storePath);
      })
      .catch((err) => {
        console.error("OAuth store persist failed:", err);
      });
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of Object.entries(this.data.codes)) {
      if (v.expires_at < now) delete this.data.codes[k];
    }
    for (const [k, v] of Object.entries(this.data.tokens)) {
      if (v.expires_at + 30 * 24 * 60 * 60 * 1000 < now) {
        delete this.data.tokens[k];
        delete this.data.refresh_index[v.refresh_token];
      }
    }
  }

  registerClient(input: {
    client_name?: string;
    redirect_uris: string[];
    token_endpoint_auth_method?: OAuthClient["token_endpoint_auth_method"];
  }): OAuthClient {
    const client: OAuthClient = {
      client_id: randomBytes(16).toString("hex"),
      client_name: input.client_name,
      redirect_uris: input.redirect_uris,
      token_endpoint_auth_method: input.token_endpoint_auth_method ?? "none",
      created_at: Date.now(),
    };
    if (client.token_endpoint_auth_method !== "none") {
      client.client_secret = randomBytes(32).toString("hex");
    }
    this.data.clients[client.client_id] = client;
    this.persist();
    return client;
  }

  getClient(client_id: string): OAuthClient | undefined {
    return this.data.clients[client_id];
  }

  createAuthCode(input: Omit<AuthCode, "code" | "expires_at">): string {
    const code = randomBytes(32).toString("base64url");
    this.data.codes[code] = {
      ...input,
      code,
      expires_at: Date.now() + CODE_TTL_MS,
    };
    this.persist();
    return code;
  }

  consumeAuthCode(code: string): AuthCode | undefined {
    const entry = this.data.codes[code];
    if (!entry) return undefined;
    delete this.data.codes[code];
    this.persist();
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  issueTokens(input: {
    client_id: string;
    scope?: string;
    easypanel_token: string;
    easypanel_url: string;
    user_email: string;
  }): AccessToken {
    const access_token = randomBytes(32).toString("base64url");
    const refresh_token = randomBytes(32).toString("base64url");
    const entry: AccessToken = {
      access_token,
      refresh_token,
      client_id: input.client_id,
      scope: input.scope,
      easypanel_token: input.easypanel_token,
      easypanel_url: input.easypanel_url,
      user_email: input.user_email,
      expires_at: Date.now() + ACCESS_TTL_MS,
    };
    this.data.tokens[access_token] = entry;
    this.data.refresh_index[refresh_token] = access_token;
    this.persist();
    return entry;
  }

  getAccessToken(access_token: string): AccessToken | undefined {
    const entry = this.data.tokens[access_token];
    if (!entry) return undefined;
    if (entry.expires_at < Date.now()) return undefined;
    return entry;
  }

  rotateRefreshToken(refresh_token: string, client_id: string): AccessToken | undefined {
    const existingAccess = this.data.refresh_index[refresh_token];
    if (!existingAccess) return undefined;
    const prior = this.data.tokens[existingAccess];
    if (!prior || prior.client_id !== client_id) return undefined;

    delete this.data.tokens[existingAccess];
    delete this.data.refresh_index[refresh_token];

    return this.issueTokens({
      client_id: prior.client_id,
      scope: prior.scope,
      easypanel_token: prior.easypanel_token,
      easypanel_url: prior.easypanel_url,
      user_email: prior.user_email,
    });
  }

  revokeToken(token: string): void {
    const access = this.data.tokens[token] ? token : this.data.refresh_index[token];
    if (!access) return;
    const entry = this.data.tokens[access];
    if (entry) delete this.data.refresh_index[entry.refresh_token];
    delete this.data.tokens[access];
    this.persist();
  }
}

export function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input).digest("base64url");
}
