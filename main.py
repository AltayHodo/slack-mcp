#!/usr/bin/env python3
"""
Slack MCP Server
Main entry point for the Slack Model Context Protocol server.

Features secure multi-user authentication via OAuth 2.1 proxy authorization
server, and multi-tenant hosting: one process can serve several Slack
workspaces at once, each mounted under its own URL path prefix
(e.g. /duolingo/mcp and /handshake/mcp), each with its own Slack app
credentials and optional workspace pin.
"""

import logging
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from importlib import metadata

import slack_tools
from auth.oauth_config import SlackOAuthConfig, load_tenants
from auth.token_store import TokenStore, create_token_store_from_env
from fastapi import Request
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount, Route

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def register_tools(server: FastMCP) -> None:
    """Register the Slack tool set on a FastMCP server instance.

    Each tool uses the authenticated user's credentials from the current
    request session (set by AuthInfoMiddleware from the validated MCP token
    claims), so the same tool implementations work for every tenant.
    """

    @server.tool()
    def slack_get_channel_messages(
        channel_id: str,
        limit: int = 100,
        cursor: str = None,
        compact: bool = True,
    ) -> dict:
        """
        Get messages from a Slack channel.

        Uses the authenticated user's credentials from the current session.
        Authentication is handled automatically - no user_id required.

        Args:
            channel_id: Channel ID or name (e.g., 'C1234567890' or '#general')
            limit: Maximum number of messages to retrieve (default: 100, max: 1000)
            cursor: Pagination cursor from previous response (optional)
            compact: If True (default), returns only essential fields. Set to False for full Slack API response.

        Returns:
            Dictionary with messages and pagination info
        """
        return slack_tools.get_channel_messages(channel_id, limit, cursor, compact)

    @server.tool()
    def slack_get_thread_replies(
        channel_id: str,
        thread_ts: str,
        limit: int = 100,
        cursor: str = None,
        compact: bool = True,
    ) -> dict:
        """
        Get replies from a Slack thread.

        Uses the authenticated user's credentials from the current session.
        Authentication is handled automatically - no user_id required.

        Args:
            channel_id: Channel ID or name where the thread exists
            thread_ts: Timestamp of the parent message (e.g., '1234567890.123456')
            limit: Maximum number of replies to retrieve (default: 100, max: 1000)
            cursor: Pagination cursor from previous response (optional)
            compact: If True (default), returns only essential fields. Set to False for full Slack API response.

        Returns:
            Dictionary with thread messages and pagination info
        """
        return slack_tools.get_thread_replies(channel_id, thread_ts, limit, cursor, compact)

    @server.tool()
    def slack_search_messages(
        query: str,
        count: int = 20,
        page: int = 1,
        from_user: str = None,
        in_channel: str = None,
        after_date: str = None,
        before_date: str = None,
        sort_by: str = "relevance",
        sort_order: str = "desc",
        compact: bool = True,
    ) -> dict:
        """
        Search for messages across all Slack conversations with advanced filters.

        Uses the authenticated user's credentials from the current session.
        Authentication is handled automatically - no user_id required.

        Args:
            query: Search query string (can be empty if using only filters)
            count: Number of results per page (default: 20, max: 100)
            page: Page number for pagination (default: 1)
            from_user: Filter by user ID or username (e.g., 'U123ABC' or '@john')
            in_channel: Filter by channel ID or name (e.g., 'C123ABC' or '#general')
            after_date: Messages after this date (YYYY-MM-DD or relative like '7d', '1m')
            before_date: Messages before this date (YYYY-MM-DD or relative)
            sort_by: Sort results by 'timestamp' or 'relevance' (default: 'relevance')
            sort_order: Sort order 'asc' or 'desc' (default: 'desc')

        Returns:
            Dictionary with search results and pagination info

        Examples:
            - Search in last 7 days: slack_search_messages("important", after_date="7d")
            - Search from user in channel: slack_search_messages("meeting", from_user="@john", in_channel="#team")
            - Date range: slack_search_messages("report", after_date="2025-01-01", before_date="2025-01-31")
        """
        return slack_tools.search_messages(
            query=query,
            count=count,
            page=page,
            from_user=from_user,
            in_channel=in_channel,
            after_date=after_date,
            before_date=before_date,
            sort_by=sort_by,
            sort_order=sort_order,
            compact=compact,
        )

    @server.tool()
    def slack_get_users(
        user_id: str = None,
        limit: int = 100,
        cursor: str = None,
        compact: bool = True,
    ) -> dict:
        """
        Get users from Slack workspace.

        This is a dual-mode tool:
        - Without user_id: Lists all users in the workspace with pagination
        - With user_id: Gets detailed profile for a specific user

        Uses the authenticated user's credentials from the current session.
        Authentication is handled automatically - no user_id required.

        Args:
            user_id: Optional user ID. If provided, gets specific user profile
            limit: Maximum number of users to retrieve when listing (default: 100, max: 1000)
            cursor: Pagination cursor from previous response (for listing mode)
            compact: If True (default), returns only essential fields. Set to False for full Slack API response.

        Returns:
            Dictionary with user(s) and pagination info
            - List mode: {"ok": True, "users": [...], "next_cursor": "..."}
            - Get mode: {"ok": True, "user": {...}}
        """
        return slack_tools.get_users(user_id, limit, cursor, compact)

    @server.tool()
    def slack_get_channels(
        channel_id: str = None,
        types: str = None,
        limit: int = 100,
        cursor: str = None,
        include_members: bool = False,
        compact: bool = True,
    ) -> dict:
        """
        Get channels from Slack workspace.

        This is a dual-mode tool:
        - Without channel_id: Lists channels with optional type filter (defaults to public channels only)
        - With channel_id: Gets detailed info for a specific channel, optionally with members

        Uses the authenticated user's credentials from the current session.
        Authentication is handled automatically - no user_id required.

        Args:
            channel_id: Optional channel ID. If provided, gets specific channel info
            types: Filter by channel types when listing. Defaults to "public_channel" if not specified.
                   Examples: "public_channel,private_channel", "im,mpim" (DMs and group DMs)
            limit: Maximum number of channels to retrieve when listing (default: 100, max: 1000)
            cursor: Pagination cursor from previous response (for listing mode)
            include_members: Include member list when getting specific channel (default: False)
            compact: If True (default), returns only essential fields. Set to False for full Slack API response.

        Returns:
            Dictionary with channel(s) and pagination info
            - List mode: {"ok": True, "channels": [...], "next_cursor": "..."}
            - Get mode: {"ok": True, "channel": {...}, "members": [...]}
        """
        return slack_tools.get_channels(channel_id, types, limit, cursor, include_members, compact)


def configure_oauth(
    server: FastMCP, config: SlackOAuthConfig, token_store: TokenStore | None = None
) -> bool:
    """
    Configure the OAuth 2.1 authentication provider for one tenant's server.
    Must be called BEFORE building the tenant's http_app.

    Sets up SlackOAuthProvider (proxy pattern) and AuthInfoMiddleware for
    extracting Slack tokens from MCP token claims. The provider's base_url is
    the tenant's path-prefixed public URL, so the OAuth metadata (issuer,
    authorization_endpoint, token_endpoint, etc.) advertises URLs reachable by
    external MCP clients at the correct mount path.

    Returns True if OAuth was configured, False otherwise.
    """
    if not config.is_configured():
        logger.warning("Tenant '%s': OAuth credentials not configured — skipping", config.tenant_id or "default")
        return False

    from auth.auth_info_middleware import AuthInfoMiddleware
    from auth.slack_oauth_provider import SlackOAuthProvider
    from mcp.server.auth.settings import ClientRegistrationOptions

    # Optional Handshaker-only gate: comma-separated allowed email domains.
    # Unset = no restriction (local/dev); prod sets e.g. "joinhandshake.com".
    allowed_email_domains = [
        d for d in os.getenv("SLACK_MCP_ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()
    ]

    provider = SlackOAuthProvider(
        slack_client_id=config.client_id,
        slack_client_secret=config.client_secret,
        slack_redirect_uri=config.get_slack_callback_url(),
        slack_scopes=config.scopes,
        slack_team_id=config.team_id,
        tenant_id=config.tenant_id,
        token_store=token_store,
        allowed_email_domains=allowed_email_domains,
        base_url=config.get_oauth_base_url(),
        required_scopes=sorted(config.scopes),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=sorted(config.scopes),
            default_scopes=sorted(config.scopes),
        ),
    )
    server.auth = provider
    server.add_middleware(AuthInfoMiddleware())

    logger.info(
        "Tenant '%s': OAuth 2.1 proxy enabled (base_url=%s)",
        config.tenant_id or "default",
        config.get_oauth_base_url(),
    )
    return True


def build_tenant_app(config: SlackOAuthConfig, token_store: TokenStore | None = None):
    """Build a mountable Starlette app for one tenant."""
    name = f"Slack MCP Server [{config.tenant_id or 'default'}]"
    server = FastMCP(name)
    register_tools(server)
    configure_oauth(server, config, token_store)
    # Each tenant serves its MCP endpoint at <prefix>/mcp once mounted.
    return server.http_app(path="/mcp", transport="streamable-http")


def _root_metadata_routes(app, config: SlackOAuthConfig) -> list[Route]:
    """Build root-level aliases for a tenant's OAuth discovery metadata.

    Returns Route objects (to add to the parent app) that serve the tenant's
    well-known metadata at the absolute paths MCP clients derive per RFC
    9728/8414, rather than under the tenant mount prefix.
    """
    extra: list[Route] = []
    for route in app.routes:
        path = getattr(route, "path", "") or ""
        methods = getattr(route, "methods", None)
        if path.startswith("/.well-known/oauth-protected-resource"):
            # Advertised at root verbatim (resource path already embedded).
            extra.append(Route(path, endpoint=route.endpoint, methods=list(methods or ["GET"])))
        elif path.startswith("/.well-known/oauth-authorization-server"):
            # RFC 8414 root-inserted form: /.well-known/oauth-authorization-server/<tenant>.
            # (Clients also try the path-relative form served under the mount.)
            #
            # fastmcp 2.13.x registers the legacy exact path
            # (/.well-known/oauth-authorization-server); a future version may
            # instead register the path-aware form already suffixed with the
            # tenant. startswith() matches both so a fastmcp upgrade can't
            # silently drop the root alias. Re-register under the tenant alias
            # unless it's already there (avoid a duplicate-route collision).
            alias = f"/.well-known/oauth-authorization-server/{config.tenant_id}"
            if path != alias:
                extra.append(Route(alias, endpoint=route.endpoint, methods=list(methods or ["GET"])))
    return extra


def build_app() -> Starlette:
    """Build the parent ASGI app that mounts every configured tenant.

    Each tenant FastMCP app is mounted under its path prefix. Starlette does
    not run a mounted sub-app's lifespan automatically, so we chain every
    tenant app's lifespan (which starts/stops its MCP session manager) into
    the parent app's lifespan via an AsyncExitStack.
    """
    tenants = load_tenants()

    # One shared store for all tenants (rows are namespaced by tenant_id).
    # A misconfigured store (missing/wrong encryption key) raises here so
    # the server fails at boot instead of silently running without state.
    token_store = create_token_store_from_env()

    routes = []
    tenant_apps = []

    async def health_check(request: Request):
        """Health check endpoint for load balancer."""
        return JSONResponse({"status": "healthy", "tenants": len(tenant_apps)})

    # Register /health BEFORE the tenant mounts. Starlette matches routes in
    # definition order, and in legacy single-tenant mode a tenant mounts at ""
    # (root), which would otherwise swallow every path — including this one —
    # and the load balancer's health checks would 404.
    routes.append(Route("/health", endpoint=health_check, methods=["GET"]))

    for config in tenants:
        app = build_tenant_app(config, token_store)
        tenant_apps.append(app)
        # Empty prefix (legacy single tenant) mounts at root.
        mount_path = config.path_prefix or ""
        routes.append(Mount(mount_path, app=app))
        # Lift OAuth discovery metadata to root.
        #
        # RFC 9728/8414 put the resource/issuer path AFTER the .well-known
        # segment (e.g. /.well-known/oauth-protected-resource/duolingo/mcp),
        # so the URL a client derives lives at the server ROOT — not under the
        # tenant mount prefix. FastMCP registers these routes inside the tenant
        # app, where mounting prepends the prefix and the advertised URL 404s.
        # We re-register the metadata handlers on the parent app at the exact
        # path clients expect. The handlers return static JSON and don't depend
        # on the mount, so reusing the endpoint is safe.
        if config.path_prefix:
            routes.extend(_root_metadata_routes(app, config))
        logger.info(
            "Mounted tenant '%s' at %s (MCP endpoint: %s)",
            config.tenant_id or "default",
            mount_path or "/",
            config.mcp_path,
        )

    @asynccontextmanager
    async def lifespan(app):
        async with AsyncExitStack() as stack:
            for tenant_app in tenant_apps:
                await stack.enter_async_context(tenant_app.lifespan(tenant_app))
            yield

    return Starlette(routes=routes, lifespan=lifespan)


def safe_print(text):
    """Print to stderr safely, avoiding JSON parsing errors in MCP mode."""
    if not sys.stderr.isatty():
        logger.debug(f"[MCP Server] {text}")
        return

    try:
        print(text, file=sys.stderr)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode(), file=sys.stderr)


def main():
    """Main entry point for the Slack MCP server."""
    import uvicorn

    # Empty-safe: a present-but-empty SLACK_MCP_PORT would make int("") crash
    # before uvicorn starts (matches the fallback in SlackOAuthConfig).
    port = int(os.getenv("SLACK_MCP_PORT") or "8001")

    try:
        version = metadata.version("slack-mcp")
    except metadata.PackageNotFoundError:
        version = "dev"

    tenants = load_tenants()

    safe_print("🔧 Slack MCP Server")
    safe_print("=" * 35)
    safe_print(f"   📦 Version: {version}")
    safe_print("   🌐 Transport: HTTP (streamable)")
    safe_print(f"   🐍 Python: {sys.version.split()[0]}")
    db_url = os.getenv("SLACK_MCP_DATABASE_URL") or os.getenv("DATABASE_URL")
    db_path = os.getenv("SLACK_MCP_DB_PATH", "./data/slack-mcp.db")
    if db_url:
        persistence = "enabled (postgres)"
    elif db_path:
        persistence = f"enabled (sqlite: {db_path})"
    else:
        persistence = "DISABLED — state lost on restart"
    safe_print(f"   💾 Persistence: {persistence}")
    safe_print(f"   🏢 Tenants: {len(tenants)}")
    for config in tenants:
        status = "configured" if config.is_configured() else "NOT CONFIGURED"
        team = f", team={config.team_id}" if config.team_id else ""
        safe_print(
            f"      - '{config.tenant_id or 'default'}' → {config.get_oauth_base_url()}/mcp "
            f"[{status}{team}]"
        )
    safe_print("")
    safe_print("🛠️  Tools per tenant: slack_get_channel_messages, slack_get_thread_replies,")
    safe_print("    slack_search_messages, slack_get_users, slack_get_channels")
    safe_print("")

    app = build_app()

    try:
        safe_print(f"🚀 Starting HTTP server on :{port}")
        safe_print("✅ Ready for MCP connections")
        safe_print("")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    except KeyboardInterrupt:
        safe_print("\n👋 Server shutdown requested")
        sys.exit(0)
    except Exception as e:
        safe_print(f"\n❌ Server error: {e}")
        logger.error(f"Unexpected error running server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
