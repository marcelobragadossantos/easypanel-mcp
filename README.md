# easypanel-mcp

MCP server for [EasyPanel](https://easypanel.io) — manage your server, projects, services, databases, and domains through any MCP-compatible AI agent (Claude, Cursor, etc.).

**40 curated tools** + raw tRPC access to all **347 EasyPanel API procedures**.

## 🚀 Quick Setup (Deploy on EasyPanel)

The easiest way — deploy the MCP server as a service on your own EasyPanel. Pick an auth mode:

- **OAuth** (recommended) — users sign in with their Easypanel email/password in a browser popup. No tokens to generate or paste. Per-user access.
- **Bearer** — one shared API key + one Easypanel token baked into env vars.

### OAuth mode (browser sign-in, per-user)

1. Create a project (e.g. `mcp`), add an **App** service from GitHub `dray-supadev/easypanel-mcp`
2. Add a domain (e.g. `mcp.your-domain.com`)
3. Set environment variables:
   ```
   EASYPANEL_URL=http://easypanel:3000
   EASYPANEL_MCP_MODE=http
   EASYPANEL_AUTH_MODE=oauth
   OAUTH_ISSUER_URL=https://mcp.your-domain.com
   MCP_ACCESS_MODE=readonly
   PORT=3000
   ```
4. (Optional but recommended) Mount a volume at `/data` and set `OAUTH_STORE_PATH=/data/oauth.json` so tokens survive redeploys.
5. Deploy.

Connect Claude Desktop or another OAuth-aware MCP client:

```json
{
  "mcpServers": {
    "easypanel": { "url": "https://mcp.your-domain.com/mcp" }
  }
}
```

On first use the client will pop a browser window asking for your Easypanel credentials, then return you to Claude with an access token. No manual curl required.

> The login page calls Easypanel's `auth.login` internally and binds the session token to an opaque OAuth access token scoped to this MCP server. Credentials are never stored.

### Bearer mode (shared key, simpler)

1. Get your API token:
   ```bash
   curl -X POST https://YOUR_PANEL:3000/api/trpc/auth.login \
     -H "Content-Type: application/json" \
     -d '{"json":{"email":"you@email.com","password":"your-pass"}}'
   ```
   > If you have 2FA enabled, add `"code":"123456"` with your authenticator code.

   The response contains `"token":"xxx"` — that's your API token.

   > ⚠️ This is a **session token** that expires in 30 days. For a permanent token, use `users.generateApiToken` (see below).

2. Deploy on EasyPanel:
   ```
   EASYPANEL_URL=http://easypanel:3000
   EASYPANEL_TOKEN=your-api-token
   EASYPANEL_MCP_MODE=http
   MCP_API_KEY=your-secret-key
   MCP_ACCESS_MODE=readonly
   PORT=3000
   ```

   > **Important:** Use `http://easypanel:3000` (internal Docker network) when deploying on the same EasyPanel instance.
   > **`MCP_ACCESS_MODE`**: `readonly` blocks all write operations; set to `full` to allow mutations.
   > ⚠️ **Set `MCP_API_KEY`** — without it, anyone with the URL can control your server. Use alphanumeric only (`!`, `%`, `^` may break in env vars).

3. Connect Claude Desktop:
   ```json
   {
     "mcpServers": {
       "easypanel": {
         "url": "https://mcp.your-domain.com/mcp",
         "headers": { "Authorization": "Bearer your-secret-key" }
       }
     }
   }
   ```

Restart Claude Desktop. Done! Ask Claude to "show my projects" 🎉

## 💻 Local Setup (Alternative)

Run the MCP server locally via stdio (no deployment needed):

```bash
git clone https://github.com/dray-supadev/easypanel-mcp.git
cd easypanel-mcp
npm install && npm run build
```

```json
{
  "mcpServers": {
    "easypanel": {
      "command": "node",
      "args": ["/path/to/easypanel-mcp/dist/index.js"],
      "env": {
        "EASYPANEL_URL": "https://your-panel:3000",
        "EASYPANEL_TOKEN": "your-api-token"
      }
    }
  }
}
```

## 🔧 Available Tools (40)

### Projects
`list_projects` · `create_project` · `destroy_project` · `inspect_project`

### App Services
`create_app` · `inspect_app` · `deploy_app` · `start_app` · `stop_app` · `restart_app` · `destroy_app` · `set_app_source_image` · `set_app_source_github` · `set_app_env` · `set_app_resources`

### Databases (Postgres, MySQL, MariaDB, MongoDB, Redis)
`create_database` · `inspect_database` · `destroy_database`

### Domains & Ports
`list_domains` · `create_domain` · `delete_domain` · `create_port` · `list_ports`

### Volumes
`create_mount` · `list_mounts`

### Monitoring
`system_stats` · `service_stats` · `storage_stats`

### Docker Compose
`create_compose` · `inspect_compose` · `deploy_compose`

### System
`cleanup_docker` · `system_prune` · `restart_panel` · `reboot_server` · `list_users` · `list_certificates` · `list_nodes` · `deploy_template`

### Escape Hatch
`trpc_raw` — call any of the 347 tRPC procedures directly

## 🔒 Security

- **OAuth mode** — per-user access via browser sign-in; the MCP server acts as an OAuth 2.1 authorization server (PKCE required, dynamic client registration per RFC 7591). Access tokens are opaque and bound to the user's Easypanel session token server-side; credentials never leave this server in stored form.
- **Bearer mode** — `MCP_API_KEY` protects the endpoint, `EASYPANEL_TOKEN` is used for all API calls.
- Health endpoint (`/health`) is always public (returns no sensitive data).
- In local/stdio mode, no network auth is needed.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `EASYPANEL_URL` | ✅ | Your EasyPanel URL |
| `EASYPANEL_TOKEN` | Bearer/stdio | API token from login (not needed in OAuth mode) |
| `EASYPANEL_MCP_MODE` | For HTTP | `stdio` (default) or `http` |
| `EASYPANEL_AUTH_MODE` | No | `bearer` (default) or `oauth` |
| `MCP_API_KEY` | Bearer HTTP | Shared key protecting the endpoint |
| `OAUTH_ISSUER_URL` | OAuth | Public URL of this server (e.g. `https://mcp.example.com`) |
| `OAUTH_STORE_PATH` | No | Where to persist OAuth state (default `./.easypanel-mcp-oauth.json`) |
| `MCP_ACCESS_MODE` | No | `full` (default) or `readonly` — blocks all mutations |
| `PORT` | No | HTTP port (default: 3100) |

## OAuth Endpoints

When `EASYPANEL_AUTH_MODE=oauth`, the server exposes:

- `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata
- `GET /.well-known/oauth-protected-resource` — RFC 9728 metadata
- `POST /register` — RFC 7591 dynamic client registration
- `GET /authorize` — login page
- `POST /authorize` — credentials → authorization code (302 redirect to client)
- `POST /token` — `authorization_code` and `refresh_token` grants (S256 PKCE required)

## Generating a Permanent API Token

Session tokens from `auth.login` expire in 30 days. For a permanent token:

**Step 1.** Get your user ID:

```bash
curl -s "https://YOUR_PANEL:3000/api/trpc/users.listUsers" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

Find your email in the response and copy the `"id"` field.

**Step 2.** Generate the permanent token:

```bash
curl -s -X POST "https://YOUR_PANEL:3000/api/trpc/users.generateApiToken" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"json":{"id":"YOUR_USER_ID"}}'
```

**Step 3.** Retrieve the token — list users again:

```bash
curl -s "https://YOUR_PANEL:3000/api/trpc/users.listUsers" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

Your user now has an `"apiToken"` field — that's the permanent token. Set it as `EASYPANEL_TOKEN` in your MCP service env.

> This token **never expires** unless you revoke it via `users.revokeApiToken`.

## How It Works

EasyPanel exposes a tRPC API at `/api/trpc/`. This MCP server was built by reverse-engineering EasyPanel's frontend to extract all 347 procedure names across 43 namespaces, then mapping the most useful ones to typed MCP tools.

## Disclaimer

This tool communicates with EasyPanel's public tRPC API. Some EasyPanel features may require a valid license. Please respect [EasyPanel's licensing terms](https://easypanel.io/pricing). This project is not affiliated with or endorsed by EasyPanel.

## License

MIT
