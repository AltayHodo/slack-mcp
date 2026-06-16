# Slack MCP Server

A read-only MCP (Model Context Protocol) server for Slack with OAuth 2.1 authentication.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Demo

https://github.com/user-attachments/assets/211bd428-209f-461a-b9a1-9cc85fd7c438

### Available Tools

- `slack_get_channel_messages` - Retrieve messages from channels
- `slack_get_thread_replies` - Get conversation thread replies
- `slack_search_messages` - Advanced message search with filters
- `slack_get_users` - List workspace users or get specific profiles
- `slack_get_channels` - List channels or get detailed info

## Quick Start

### 1. Create Slack App

1. Visit [Slack API Apps](https://api.slack.com/apps) and create a new app
2. Under **App Credentials**, copy your `Client ID` and `Client Secret`
3. Navigate to **OAuth & Permissions** and add these [**User Token Scopes**](https://docs.slack.dev/reference/scopes/): `channels:history` `groups:history` `im:history` `mpim:history` `channels:read` `groups:read` `im:read` `mpim:read` `users:read` `users:read.email` `search:read`
4. Add **Redirect URL** under **OAuth & Permissions**:
   - For local testing: Use an HTTPS proxy like ngrok (E.g: `https://abc123.ngrok.io/oauth2callback`). See local development setup below.
   - For production: `https://your-domain.com/oauth2callback`

### 2. Installation

```bash
uv sync
```

### 3. Local Development Setup (HTTPS Proxy)

Slack requires HTTPS for OAuth callbacks. For local development, use ngrok or a similar HTTPS proxy:

```bash
# Visit https://ngrok.com/ to download ngrok and start the proxy
ngrok http 8001
```

Copy the HTTPS forwarding URL (e.g., `https://abc123.ngrok.io/oauth2callback`) and add it as a Redirect URL in your Slack app settings.

### 4. Configuration

Set required environment variables:

```bash
export SLACK_CLIENT_ID="your_client_id"
export SLACK_CLIENT_SECRET="your_client_secret"
# Use https://your-domain.com for production.
export SLACK_MCP_BASE_URI="http://localhost"
# Use https://your-domain.com for production.
export SLACK_EXTERNAL_URL="https://abc123.ngrok.io"
# Optional, if you want to run the MCP server on a different port.
export SLACK_MCP_PORT=8001
# Required: encrypts persisted OAuth state at rest (see Persistence below).
export SLACK_MCP_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

### 5. Run the Server

```bash
uv run python main.py
```

The server will start on `http://localhost:8001` by default. Make sure your ngrok proxy is running alongside it for OAuth to work.

### 6. Configure Your MCP Client

Add to your MCP client configuration (e.g. ~/.cursor/mcp.json for Cursor):

```json
{
  "mcpServers": {
    "slack": { "url": "http://localhost:8001/mcp", "transport": "http" }
  }
}
```

### 7. Authenticate

Authentication happens automatically via OAuth 2.1 when your MCP client first connects. Your client will open a browser window for Slack authorization — approve access and you're ready to go.

## Persistence

OAuth state — DCR client registrations, MCP access/refresh tokens, and the
Slack user tokens they map to — is persisted so server restarts don't log
everyone out (or worse, invalidate the client registration MCP clients cache,
which forces users to re-add the connector under a new name). Values are
encrypted at rest with a Fernet key regardless of backend.

Two backends are supported, selected by environment:

- **Postgres** (production) — set `SLACK_MCP_DATABASE_URL` to a libpq
  connection string. Use this for any hosted/multi-replica deployment; state
  lives in a managed database (e.g. GCP Cloud SQL), not in the container.
- **SQLite** (local dev / single instance) — used when `SLACK_MCP_DATABASE_URL`
  is unset. `SLACK_MCP_DB_PATH` sets the file path (default
  `./data/slack-mcp.db`); requires a persistent volume in a container.

Settings:

- `SLACK_MCP_ENCRYPTION_KEY` (required for either backend): generate with
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
  If the key is lost, wipe the persisted state and users re-authenticate once.
- `SLACK_MCP_DATABASE_URL` (optional): Postgres DSN; takes precedence over SQLite.
- `SLACK_MCP_DB_PATH` (optional): SQLite file path. Set to an empty string
  (with no `SLACK_MCP_DATABASE_URL`) to disable persistence entirely.

What does NOT survive a restart: in-flight OAuth flows (pending
authorizations and unredeemed auth codes) — anyone mid-flow just restarts
the browser flow.

## Deployment

For production, run it in a container backed by managed Postgres (no volume
needed — state lives in the database):

```bash
docker build -t slack-mcp .
docker run -p 8001:8001 \
  -e SLACK_MCP_BASE_URI="https://your-domain.com" \
  -e SLACK_EXTERNAL_URL="https://your-domain.com" \
  -e SLACK_MCP_ENCRYPTION_KEY="your_fernet_key" \
  -e SLACK_MCP_DATABASE_URL="postgresql://user:pass@host:5432/slackmcp" \
  -e SLACK_TENANTS='[{"id":"...","client_id":"...","client_secret":"...","team_id":"..."}]' \
  slack-mcp
```

For a single-instance/local container on SQLite instead, drop
`SLACK_MCP_DATABASE_URL` and mount a volume at `/app/data` so the database file
survives container replacement (`-v slack-mcp-data:/app/data`).

## Development

Run tests with `uv run pytest`.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Duolingo is hiring! Apply at https://www.duolingo.com/careers
