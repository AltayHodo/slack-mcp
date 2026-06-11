#!/usr/bin/env bash
# Multi-tenant runner: one process serving every tenant in SLACK_TENANTS.
# Loads .env.tenants (gitignored) and starts the server via uv.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"

if [ ! -f .env.tenants ]; then
  echo "Missing .env.tenants — copy .env.tenants.example to .env.tenants and fill it in."
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env.tenants
set +a

missing=0
for var in SLACK_EXTERNAL_URL SLACK_TENANTS; do
  if [ -z "${!var:-}" ]; then echo "Missing $var in .env.tenants"; missing=1; fi
done
[ "$missing" -eq 0 ] || exit 1

echo "Starting multi-tenant Slack MCP server on :${SLACK_MCP_PORT:-8001}  (external: $SLACK_EXTERNAL_URL)"
exec uv run python main.py
