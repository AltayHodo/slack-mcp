"""
Proxy OAuth Authorization Server for Slack MCP.

The MCP server acts as its own OAuth 2.1 authorization server and proxies
the Slack OAuth flow internally. MCP clients do standard OAuth 2.1 with
the MCP server (which publishes discoverable metadata), and the server
handles Slack authentication behind the scenes.

The xoxp-* Slack token never leaves the server. MCP clients only see
MCP-issued tokens.
"""

import asyncio
import json
import logging
import secrets
import time
from html import escape as html_escape
from urllib.parse import quote

from fastmcp.server.auth.auth import AccessToken as FastMCPAccessToken
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from auth.token_store import (
    KIND_ACCESS_TOKEN,
    KIND_CLIENT,
    KIND_REFRESH_TOKEN,
    KIND_SLACK_TOKEN,
    KIND_TOKEN_LINK,
    TokenStore,
)
from slack_sdk import WebClient
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)


class SlackOAuthProvider(InMemoryOAuthProvider):
    """
    OAuth 2.1 Authorization Server that proxies Slack OAuth internally.

    Flow:
    1. MCP client discovers endpoints via /.well-known/oauth-authorization-server
    2. MCP client calls /authorize
    3. Provider redirects user to Slack's OAuth page
    4. Slack redirects back to /oauth2callback with a code
    5. Provider exchanges code for xoxp-* token (stored server-side)
    6. Provider redirects client to its redirect_uri with an MCP auth code
    7. MCP client exchanges MCP auth code for MCP-issued access token
    8. Tool calls use MCP token; provider looks up stored xoxp-* token
    """

    def __init__(
        self,
        slack_client_id: str,
        slack_client_secret: str,
        slack_redirect_uri: str,
        slack_scopes: list[str],
        slack_team_id: str | None = None,
        tenant_id: str = "",
        token_store: TokenStore | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._slack_client_id = slack_client_id
        self._slack_client_secret = slack_client_secret
        self._slack_redirect_uri = slack_redirect_uri
        self._slack_scopes = slack_scopes
        # Optional Slack workspace (team) ID. When set, the authorize URL pins
        # the OAuth flow to this workspace so a multi-tenant deployment routes
        # each mount to its intended workspace deterministically.
        self._slack_team_id = slack_team_id

        # internal_state -> {client_id, redirect_uri, state, code_challenge, scopes, created_at}
        self._pending_authorizations: dict[str, dict] = {}
        # MCP access_token string -> {token: "xoxp-...", user_id: "U..."}
        self._slack_tokens: dict[str, dict] = {}
        # TTL for pending authorizations and code-keyed slack tokens (10 minutes)
        self._pending_ttl = 600

        # Optional write-through persistence. The in-memory dicts above (and
        # the parent's) remain the runtime source of truth; the store mirrors
        # long-lived state so restarts don't wipe client registrations and
        # tokens. None disables persistence (current in-memory behavior).
        self._tenant_id = tenant_id
        self._token_store = token_store
        self._hydrate_from_store()

    # ----- persistence helpers -------------------------------------------

    def _db_put(self, kind: str, key: str, value: str, expires_at: float | None = None):
        if self._token_store is not None:
            self._token_store.put(self._tenant_id, kind, key, value, expires_at)

    def _db_delete(self, kind: str, key: str):
        if self._token_store is not None:
            self._token_store.delete(self._tenant_id, kind, key)

    def _hydrate_from_store(self):
        """Load persisted OAuth state into the in-memory dicts at startup."""
        store = self._token_store
        if store is None:
            return
        now = time.time()

        for key, raw in store.get_all(self._tenant_id, KIND_CLIENT).items():
            self.clients[key] = OAuthClientInformationFull.model_validate_json(raw)

        for key, raw in store.get_all(self._tenant_id, KIND_ACCESS_TOKEN).items():
            token = AccessToken.model_validate_json(raw)
            if token.expires_at is not None and token.expires_at < now:
                continue  # row is removed by purge_expired
            self.access_tokens[key] = token

        for key, raw in store.get_all(self._tenant_id, KIND_REFRESH_TOKEN).items():
            token = RefreshToken.model_validate_json(raw)
            if token.expires_at is not None and token.expires_at < now:
                continue
            self.refresh_tokens[key] = token

        # Rebuild both link maps even when the access token itself has
        # expired: the refresh flow uses refresh -> access to find the old
        # Slack token, mirroring the in-memory "refreshable" semantics in
        # _cleanup_expired. Links whose refresh token is gone are dead —
        # drop their rows so they don't accumulate.
        for access_key, refresh_key in store.get_all(self._tenant_id, KIND_TOKEN_LINK).items():
            if refresh_key in self.refresh_tokens:
                self._access_to_refresh_map[access_key] = refresh_key
                self._refresh_to_access_map[refresh_key] = access_key
            else:
                store.delete(self._tenant_id, KIND_TOKEN_LINK, access_key)

        # Keep Slack tokens still reachable via a live access token or a
        # refreshable link (same retention rule as _cleanup_expired).
        refreshable = set(self._refresh_to_access_map.values())
        for key, raw in store.get_all(self._tenant_id, KIND_SLACK_TOKEN).items():
            if key in self.access_tokens or key in refreshable:
                self._slack_tokens[key] = json.loads(raw)
            else:
                store.delete(self._tenant_id, KIND_SLACK_TOKEN, key)

        logger.info(
            "Tenant '%s': hydrated %d client(s), %d access token(s), "
            "%d refresh token(s), %d Slack token(s) from %s",
            self._tenant_id or "default",
            len(self.clients),
            len(self.access_tokens),
            len(self.refresh_tokens),
            len(self._slack_tokens),
            store.db_path,
        )

    def _persist_issued_tokens(self, oauth_token: OAuthToken):
        """Mirror a freshly issued access/refresh token pair to the store."""
        access = self.access_tokens.get(oauth_token.access_token)
        if access is not None:
            self._db_put(
                KIND_ACCESS_TOKEN,
                access.token,
                access.model_dump_json(),
                expires_at=access.expires_at,
            )
        refresh = (
            self.refresh_tokens.get(oauth_token.refresh_token)
            if oauth_token.refresh_token
            else None
        )
        if refresh is not None:
            self._db_put(
                KIND_REFRESH_TOKEN,
                refresh.token,
                refresh.model_dump_json(),
                expires_at=refresh.expires_at,
            )
            self._db_put(KIND_TOKEN_LINK, oauth_token.access_token, refresh.token)

    # ----- OAuth provider overrides ---------------------------------------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a client and persist the registration.

        Persisting DCR registrations is the core restart fix: MCP clients
        cache their client_id, and when a restarted server forgets it the
        only client-side recovery is re-adding the connector under a new
        name. UPSERT also covers RFC 7591 re-registration.
        """
        await super().register_client(client_info)
        if client_info.client_id is not None:
            self._db_put(KIND_CLIENT, client_info.client_id, client_info.model_dump_json())

    def _revoke_internal(
        self, access_token_str: str | None = None, refresh_token_str: str | None = None
    ):
        """Revoke tokens and mirror the deletions to the store.

        Single choke point: the parent routes explicit revocation, refresh
        rotation, and lazy expiry cleanup through here. The full pair must
        be resolved from the link maps BEFORE super() pops them.
        """
        access = access_token_str or (
            self._refresh_to_access_map.get(refresh_token_str) if refresh_token_str else None
        )
        refresh = refresh_token_str or (
            self._access_to_refresh_map.get(access_token_str) if access_token_str else None
        )

        super()._revoke_internal(
            access_token_str=access_token_str, refresh_token_str=refresh_token_str
        )

        if access:
            self._db_delete(KIND_ACCESS_TOKEN, access)
            self._db_delete(KIND_TOKEN_LINK, access)
        if refresh:
            self._db_delete(KIND_REFRESH_TOKEN, refresh)

    def _cleanup_expired(self):
        """Remove expired pending authorizations and stale Slack tokens."""
        now = time.time()
        expired_pending = [
            k
            for k, v in self._pending_authorizations.items()
            if now - v.get("created_at", 0) > self._pending_ttl
        ]
        for k in expired_pending:
            del self._pending_authorizations[k]

        # Clean up code-keyed entries (unredeemed auth codes)
        expired_codes = [
            k
            for k, v in self._slack_tokens.items()
            if k.startswith("code:") and now - v.get("created_at", 0) > self._pending_ttl
        ]
        for k in expired_codes:
            del self._slack_tokens[k]

        # Clean up access-token-keyed entries whose MCP token has expired
        # AND is no longer referenced by any refresh token (needed for refresh flow)
        refreshable = set(self._refresh_to_access_map.values())
        expired_access = [
            k
            for k in self._slack_tokens
            if not k.startswith("code:") and k not in self.access_tokens and k not in refreshable
        ]
        for k in expired_access:
            del self._slack_tokens[k]
            self._db_delete(KIND_SLACK_TOKEN, k)

        if self._token_store is not None:
            self._token_store.purge_expired()

        total_cleaned = len(expired_pending) + len(expired_codes) + len(expired_access)
        if total_cleaned:
            logger.debug(
                "Cleaned up %d expired pending auths, %d expired code tokens, "
                "%d expired access tokens",
                len(expired_pending),
                len(expired_codes),
                len(expired_access),
            )

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Redirect the user to Slack's OAuth page instead of auto-approving.

        Stores the pending authorization (client redirect_uri, state, code_challenge, scopes)
        keyed by an internal state token, then returns Slack's authorize URL.
        """
        self._cleanup_expired()

        internal_state = secrets.token_urlsafe(32)

        self._pending_authorizations[internal_state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes or [],
            "resource": params.resource,
            "created_at": time.time(),
        }

        user_scopes = ",".join(self._slack_scopes)
        slack_auth_url = (
            f"https://slack.com/oauth/v2/authorize"
            f"?client_id={quote(self._slack_client_id, safe='')}"
            f"&user_scope={quote(user_scopes, safe='')}"
            f"&redirect_uri={quote(self._slack_redirect_uri, safe='')}"
            f"&state={quote(internal_state, safe='')}"
        )
        # Pin to a specific workspace when configured, so multi-tenant mounts
        # route each operator to the intended workspace instead of relying on
        # whichever workspace Slack's picker defaults to.
        if self._slack_team_id:
            slack_auth_url += f"&team={quote(self._slack_team_id, safe='')}"

        logger.info("Redirecting to Slack OAuth for client %s", client.client_id)
        return slack_auth_url

    def _error_redirect(self, pending: dict, error: str, description: str) -> HTMLResponse:
        """Redirect back to the MCP client's redirect_uri with error params.

        Uses the same HTML+JS redirect pattern as the success path so that
        custom-scheme URIs (cursor://) work in all browsers.
        """
        redirect_url = construct_redirect_uri(
            pending["redirect_uri"],
            error=error,
            error_description=description,
            state=pending["state"],
        )
        html_safe_url = html_escape(redirect_url, quote=True)
        js_safe_url = json.dumps(redirect_url).replace("</", r"<\/")
        return HTMLResponse(
            content=(
                "<!DOCTYPE html><html><head>"
                f"<meta http-equiv='refresh' content='0;url={html_safe_url}'>"
                "</head><body>"
                f"<p>Redirecting... <a href='{html_safe_url}'>Click here</a>.</p>"
                f"<script>window.location.href = {js_safe_url};</script>"
                "</body></html>"
            ),
        )

    async def _handle_slack_callback(self, request: Request):
        """
        Route handler for /oauth2callback. Receives Slack's authorization code,
        exchanges it for a xoxp-* token, stores it server-side, generates an
        MCP authorization code, and redirects to the MCP client's redirect_uri.
        """
        error = request.query_params.get("error")
        if error:
            logger.error("Slack OAuth error: %s", error)
            # Redirect back to the MCP client with error params (RFC 6749 §4.1.2.1)
            # so the client doesn't hang waiting for a callback that never arrives.
            internal_state = request.query_params.get("state")
            if internal_state:
                pending = self._pending_authorizations.pop(internal_state, None)
                if pending:
                    return self._error_redirect(
                        pending, "access_denied", f"Slack OAuth error: {error}"
                    )
            # Fallback if state is missing or pending auth not found
            return HTMLResponse(
                content=f"<h1>Slack OAuth Error</h1><p>{html_escape(error)}</p>",
                status_code=400,
            )

        slack_code = request.query_params.get("code")
        internal_state = request.query_params.get("state")

        if not slack_code or not internal_state:
            return HTMLResponse(
                content="<h1>Error</h1><p>Missing code or state parameter.</p>",
                status_code=400,
            )

        self._cleanup_expired()
        pending = self._pending_authorizations.pop(internal_state, None)
        if not pending:
            logger.error("Unknown or expired internal state: %s", internal_state)
            return HTMLResponse(
                content="<h1>Error</h1><p>Invalid or expired authorization state.</p>",
                status_code=400,
            )

        # Exchange Slack code for xoxp-* token
        try:
            slack_client = WebClient()
            response = await asyncio.to_thread(
                slack_client.oauth_v2_access,
                client_id=self._slack_client_id,
                client_secret=self._slack_client_secret,
                code=slack_code,
                redirect_uri=self._slack_redirect_uri,
            )

            if not response.get("ok"):
                slack_error = response.get("error", "unknown")
                logger.error("Slack oauth.v2.access failed: %s", slack_error)
                return self._error_redirect(
                    pending, "server_error", f"Slack token exchange failed: {slack_error}"
                )

            authed_user = response.get("authed_user", {})
            slack_token = authed_user.get("access_token")
            slack_user_id = authed_user.get("id")

            if not slack_token or not slack_user_id:
                logger.error("Missing user access_token or user ID in Slack response")
                return self._error_redirect(
                    pending, "server_error", "Slack did not return a valid user token or user ID"
                )

            logger.info("Got Slack token for user %s", slack_user_id)

        except Exception as e:
            logger.error("Error exchanging Slack code: %s", e, exc_info=True)
            return self._error_redirect(
                pending, "server_error", "Failed to exchange Slack authorization code"
            )

        # Generate an MCP authorization code
        client_id = pending["client_id"]
        client = await self.get_client(client_id)
        if not client:
            logger.error("Client %s not found during callback", client_id)
            return self._error_redirect(pending, "server_error", "Client not found")

        mcp_code_value = f"mcp_auth_{secrets.token_hex(20)}"

        auth_code = AuthorizationCode(
            code=mcp_code_value,
            client_id=client_id,
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            scopes=pending["scopes"],
            expires_at=time.time() + 300,  # 5 minutes
            code_challenge=pending["code_challenge"],
            resource=pending.get("resource"),
        )
        self.auth_codes[mcp_code_value] = auth_code

        # Store the Slack token keyed by the MCP auth code temporarily;
        # it will be moved to the access token key during exchange
        self._slack_tokens[f"code:{mcp_code_value}"] = {
            "token": slack_token,
            "user_id": slack_user_id,
            "created_at": time.time(),
        }

        # Redirect to the MCP client's redirect_uri with the MCP auth code.
        # Use an HTML page with JavaScript redirect instead of a 302 redirect
        # because some browsers strip query parameters from custom protocol
        # scheme URLs (like cursor://) when handling server-side redirects.
        redirect_url = construct_redirect_uri(
            pending["redirect_uri"],
            code=mcp_code_value,
            state=pending["state"],
        )

        logger.info(
            "Redirecting to MCP client with auth code for user %s",
            slack_user_id,
        )

        # Use html_escape for HTML attributes, json.dumps for JS string.
        # html.escape() turns & → &amp; which is correct in HTML attributes
        # but inside <script>, JS doesn't decode HTML entities, so we need
        # json.dumps() to produce a safe JS string literal.
        html_safe_url = html_escape(redirect_url, quote=True)
        js_safe_url = json.dumps(redirect_url).replace("</", r"<\/")  # produces "..." with escaping

        html_content = (
            "<!DOCTYPE html><html><head>"
            f"<meta http-equiv='refresh' content='0;url={html_safe_url}'>"
            "</head><body>"
            "<p>Completing authentication... "
            f"<a href='{html_safe_url}'>Click here</a> if not redirected.</p>"
            f"<script>window.location.href = {js_safe_url};</script>"
            "</body></html>"
        )

        return HTMLResponse(content=html_content)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """
        Exchange MCP auth code for MCP tokens, then associate the stored
        Slack token with the new MCP access token.
        """
        # Retrieve the Slack token stored during callback (don't remove yet —
        # if super() fails, we'd lose the token permanently)
        code_key = f"code:{authorization_code.code}"
        slack_info = self._slack_tokens.get(code_key)

        # Call parent to generate MCP tokens
        oauth_token = await super().exchange_authorization_code(client, authorization_code)

        # Only now remove the code-keyed entry and associate with access token
        if slack_info:
            self._slack_tokens.pop(code_key, None)
            self._slack_tokens[oauth_token.access_token] = slack_info
            # code:-keyed entries are never persisted, so there is no DB
            # delete to mirror — only the access-token-keyed association.
            self._db_put(KIND_SLACK_TOKEN, oauth_token.access_token, json.dumps(slack_info))
            logger.debug(
                "Associated Slack token for user %s with MCP access token",
                slack_info.get("user_id"),
            )
        else:
            logger.warning(
                "No Slack token found for auth code %s — MCP token will lack Slack access",
                authorization_code.code[:8] + "...",
            )

        self._persist_issued_tokens(oauth_token)
        return oauth_token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchange refresh token for new MCP tokens, then transfer the Slack
        token association to the new MCP access token.
        """
        # Find the old access token associated with this refresh token
        # (don't remove yet — if super() fails, we'd lose the token permanently)
        old_access_token = self._refresh_to_access_map.get(refresh_token.token)
        old_slack_info = None
        if old_access_token:
            old_slack_info = self._slack_tokens.get(old_access_token)

        # Call parent to generate new MCP tokens
        oauth_token = await super().exchange_refresh_token(client, refresh_token, scopes)

        # Only now remove old entry and transfer the Slack token to the new access token
        if old_slack_info:
            if old_access_token:
                self._slack_tokens.pop(old_access_token, None)
                self._db_delete(KIND_SLACK_TOKEN, old_access_token)
            self._slack_tokens[oauth_token.access_token] = old_slack_info
            self._db_put(KIND_SLACK_TOKEN, oauth_token.access_token, json.dumps(old_slack_info))
            logger.debug(
                "Transferred Slack token for user %s to new MCP access token",
                old_slack_info.get("user_id"),
            )
        else:
            logger.warning(
                "No Slack token found during refresh — new MCP token will lack Slack access"
            )

        # super() already revoked the old pair via our _revoke_internal
        # override, which mirrored those deletions to the store.
        self._persist_issued_tokens(oauth_token)
        return oauth_token

    async def load_access_token(self, token: str):
        """
        Load access token and attach Slack token info to claims.

        The SDK's AccessToken (from mcp.server.auth.provider) has no `claims`
        field. We reconstruct using FastMCP's AccessToken which adds `claims: dict`.
        """
        access_token = await super().load_access_token(token)
        if access_token is None:
            return None

        # Reconstruct as FastMCP's AccessToken which has a `claims` dict.
        # super() may return the SDK's AccessToken (no claims field).
        claims = {}
        slack_info = self._slack_tokens.get(token)
        if slack_info:
            claims["slack_token"] = slack_info["token"]
            claims["slack_user_id"] = slack_info["user_id"]

        return FastMCPAccessToken(
            token=access_token.token,
            client_id=access_token.client_id,
            scopes=access_token.scopes,
            expires_at=access_token.expires_at,
            claims=claims,
        )

    def get_routes(self, **kwargs) -> list[Route]:
        """
        Get standard OAuth routes plus the Slack callback route.
        """
        routes = super().get_routes(**kwargs)

        # Add the Slack OAuth callback route
        slack_callback_route = Route(
            "/oauth2callback",
            endpoint=self._handle_slack_callback,
            methods=["GET"],
        )
        routes.append(slack_callback_route)

        return routes
