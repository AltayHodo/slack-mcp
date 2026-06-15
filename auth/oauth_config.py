"""
OAuth Configuration Management for Slack MCP server.
Handles OAuth 2.1 proxy authorization server configuration.

Supports both single-tenant (legacy, root-mounted) and multi-tenant
(path-mounted) deployments. In multi-tenant mode, one process serves
several Slack workspaces, each under its own URL path prefix
(e.g. https://host/duolingo/mcp and https://host/handshake/mcp), each
with its own Slack app credentials and optional workspace pin.
"""

import json
import logging
import os
from threading import RLock
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Default user-token scopes required by the tools. Shared by every tenant.
DEFAULT_SCOPES = [
    "channels:history",
    "groups:history",
    "im:history",
    "mpim:history",
    "channels:read",
    "groups:read",
    "im:read",
    "mpim:read",
    "users:read",
    "users:read.email",
    "search:read",
]

# Sentinel so callers can distinguish "argument not provided" (read env)
# from "argument explicitly None" (no external URL).
_UNSET = object()


class SlackOAuthConfig:
    """
    Centralized OAuth configuration for a single Slack tenant.

    Uses OAuth 2.1 proxy authorization server pattern where this MCP server
    acts as the authorization server for MCP clients, proxying to Slack.

    A tenant may be mounted under a URL path prefix (``tenant_id``). When set,
    every advertised OAuth endpoint and the Slack callback URL are prefixed
    with ``/<tenant_id>`` so the metadata matches where the app is actually
    mounted in the parent ASGI app.
    """

    def __init__(
        self,
        *,
        client_id=None,
        client_secret=None,
        tenant_id: str = "",
        team_id=None,
        base_uri=None,
        port=None,
        external_url=_UNSET,
        scopes=None,
    ):
        # Base server configuration (fall back to env for backward compatibility)
        raw_base = base_uri if base_uri is not None else os.getenv("SLACK_MCP_BASE_URI", "http://localhost")
        self.base_uri = raw_base.rstrip("/")
        # Treat an unset OR empty SLACK_MCP_PORT as "use the default" — a
        # present-but-empty env var would otherwise make int("") crash at boot.
        raw_port = port if port is not None else os.getenv("SLACK_MCP_PORT")
        self.port = int(raw_port) if raw_port else 8001

        # Determine host base URL (with port if not already specified in base_uri).
        # Only append port for non-standard scheme/port combos (e.g. http://localhost
        # needs :8001, but https://slack-mcp.internal.example should NOT get it appended).
        parsed = urlparse(self.base_uri)
        if parsed.port:
            self.base_url = self.base_uri
        elif (parsed.scheme == "https" and self.port == 443) or (
            parsed.scheme == "http" and self.port == 80
        ):
            self.base_url = self.base_uri
        else:
            self.base_url = f"{self.base_uri}:{self.port}"

        # External URL for reverse proxy scenarios
        if external_url is _UNSET:
            raw_external = os.getenv("SLACK_EXTERNAL_URL")
        else:
            raw_external = external_url
        self.external_url = raw_external.rstrip("/") if raw_external else None

        # OAuth client configuration
        self.client_id = client_id if client_id is not None else os.getenv("SLACK_CLIENT_ID")
        self.client_secret = (
            client_secret if client_secret is not None else os.getenv("SLACK_CLIENT_SECRET")
        )

        # Tenant identity. Empty tenant_id == legacy single-tenant (root mount).
        self.tenant_id = (tenant_id or "").strip("/")
        # Slack workspace (team) ID to pin the OAuth flow to, if known.
        self.team_id = team_id if team_id is not None else os.getenv("SLACK_TEAM_ID")

        # OAuth scopes required for the tools (user token scopes)
        self.scopes = list(scopes) if scopes else list(DEFAULT_SCOPES)

    @property
    def path_prefix(self) -> str:
        """URL path prefix for this tenant ('' for legacy root mount)."""
        return f"/{self.tenant_id}" if self.tenant_id else ""

    @property
    def mcp_path(self) -> str:
        """Path of the MCP streamable-http endpoint for this tenant."""
        return f"{self.path_prefix}/mcp"

    def is_configured(self) -> bool:
        """Check if OAuth is properly configured."""
        return bool(self.client_id and self.client_secret)

    def get_oauth_base_url(self) -> str:
        """Get OAuth base URL for constructing OAuth endpoints.

        Uses SLACK_EXTERNAL_URL if set (for reverse proxy scenarios),
        otherwise falls back to constructed base_url with port. The tenant
        path prefix is always appended so advertised endpoints match where
        the tenant app is mounted.
        """
        host = self.external_url if self.external_url else self.base_url
        return f"{host}{self.path_prefix}"

    def get_slack_callback_url(self) -> str:
        """Get the Slack OAuth callback URL for this tenant.

        In OAuth 2.1 proxy mode, the tenant's /oauth2callback endpoint
        receives the callback from Slack after user authorization. This must
        be registered as a Redirect URL in the tenant's Slack app settings.
        """
        return f"{self.get_oauth_base_url()}/oauth2callback"


def load_tenants() -> list[SlackOAuthConfig]:
    """Load the tenant list for this deployment.

    Multi-tenant mode: set ``SLACK_TENANTS`` to a JSON array, e.g.
        [
          {"id": "duolingo",  "client_id": "...", "client_secret": "...", "team_id": "T_AAA"},
          {"id": "handshake", "client_id": "...", "client_secret": "...", "team_id": "T_BBB"}
        ]
    Each entry's ``client_secret`` may instead be given as ``client_secret_env``
    (the name of an env var holding the secret) to keep secrets out of the
    manifest blob.

    Single-tenant mode (legacy): if ``SLACK_TENANTS`` is unset, a single
    root-mounted tenant is built from SLACK_CLIENT_ID / SLACK_CLIENT_SECRET.
    """
    base_uri = os.getenv("SLACK_MCP_BASE_URI", "http://localhost")
    port = os.getenv("SLACK_MCP_PORT")
    external_url = os.getenv("SLACK_EXTERNAL_URL")

    raw = os.getenv("SLACK_TENANTS")
    if raw:
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"SLACK_TENANTS is not valid JSON: {exc}") from exc

        tenants = []
        seen_ids = set()
        for entry in entries:
            tenant_id = (entry.get("id") or "").strip("/")
            if not tenant_id:
                raise ValueError("Every SLACK_TENANTS entry needs a non-empty 'id'")
            if tenant_id in seen_ids:
                raise ValueError(f"Duplicate tenant id in SLACK_TENANTS: {tenant_id}")
            seen_ids.add(tenant_id)

            secret = entry.get("client_secret")
            if not secret and entry.get("client_secret_env"):
                secret = os.getenv(entry["client_secret_env"])

            tenants.append(
                SlackOAuthConfig(
                    client_id=entry.get("client_id"),
                    client_secret=secret,
                    tenant_id=tenant_id,
                    team_id=entry.get("team_id"),
                    base_uri=base_uri,
                    port=port,
                    external_url=external_url,
                )
            )
        logger.info("Loaded %d tenant(s) from SLACK_TENANTS: %s", len(tenants), sorted(seen_ids))
        return tenants

    # Legacy single-tenant fallback (root mount)
    logger.info("SLACK_TENANTS not set — running single-tenant (legacy root mount)")
    return [
        SlackOAuthConfig(
            tenant_id="",
            base_uri=base_uri,
            port=port,
            external_url=external_url,
        )
    ]


# Global configuration instance with thread-safe access (legacy single-tenant API)
_oauth_config = None
_oauth_config_lock = RLock()


def get_oauth_config() -> SlackOAuthConfig:
    """Get the global OAuth configuration instance (thread-safe singleton).

    Retained for backward compatibility / single-tenant callers. Multi-tenant
    deployments should use ``load_tenants()`` instead.
    """
    global _oauth_config
    with _oauth_config_lock:
        if _oauth_config is None:
            _oauth_config = SlackOAuthConfig()
        return _oauth_config
