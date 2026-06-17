"""
Tests for the Slack OAuth callback, focused on server-side enforcement of the
workspace (team) pin. The &team= hint on the authorize URL only steers Slack's
UI; the callback must verify the returned workspace matches the tenant's pin so
a mount can't broker the wrong workspace.
"""

import asyncio
import time

import auth.slack_oauth_provider as provider_mod
from auth.slack_oauth_provider import SlackOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import HTMLResponse

PINNED = "T_PINNED"
OTHER = "T_OTHER"
REDIRECT = "http://localhost:9000/callback"


def make_provider(team_id=PINNED, allowed_email_domains=None):
    return SlackOAuthProvider(
        slack_client_id="cid",
        slack_client_secret="sec",
        slack_redirect_uri="http://localhost:8001/oauth2callback",
        slack_scopes=["search:read"],
        slack_team_id=team_id,
        tenant_id="internal",
        allowed_email_domains=allowed_email_domains,
    )


def seed_pending(provider, state="state123", client_id="client-1"):
    provider._pending_authorizations[state] = {
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "redirect_uri_provided_explicitly": True,
        "state": "client-state",
        "code_challenge": "challenge",
        "scopes": ["search:read"],
        "resource": None,
        "created_at": time.time(),
    }
    # The success path looks up the client; register a minimal one.
    provider.clients[client_id] = OAuthClientInformationFull(
        client_id=client_id,
        client_secret="x",
        redirect_uris=[REDIRECT],
    )


def patch_slack(monkeypatch, team_id, email="user@joinhandshake.com"):
    """Stub WebClient so oauth_v2_access returns a token for `team_id` and
    users_info returns a profile with `email`."""
    response = {
        "ok": True,
        "authed_user": {"access_token": "xoxp-secret", "id": "U1"},
        "team": {"id": team_id, "name": "Workspace"},
    }

    class _Fake:
        def oauth_v2_access(self, **kwargs):
            return response

        def users_info(self, **kwargs):
            return {"user": {"profile": {"email": email}}}

    monkeypatch.setattr(provider_mod, "WebClient", lambda *a, **k: _Fake())


def make_request(code="slackcode", state="state123"):
    scope = {
        "type": "http",
        "method": "GET",
        "query_string": f"code={code}&state={state}".encode(),
        "headers": [],
    }
    return Request(scope)


def test_callback_rejects_wrong_workspace(monkeypatch):
    provider = make_provider(team_id=PINNED)
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=OTHER)  # user authorized in the wrong workspace

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    assert "access_denied" in resp.body.decode()
    # No token of any kind should have been stored.
    assert provider._slack_tokens == {}


def test_callback_accepts_matching_workspace(monkeypatch):
    provider = make_provider(team_id=PINNED)
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=PINNED)

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    # The temporary code:-keyed Slack token is stored on success.
    code_keys = [k for k in provider._slack_tokens if k.startswith("code:")]
    assert len(code_keys) == 1
    assert provider._slack_tokens[code_keys[0]]["token"] == "xoxp-secret"


def test_callback_without_pin_skips_check(monkeypatch):
    # No team_id configured → legacy behavior, any workspace accepted.
    provider = make_provider(team_id=None)
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=OTHER)

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    code_keys = [k for k in provider._slack_tokens if k.startswith("code:")]
    assert len(code_keys) == 1


def test_callback_rejects_missing_team_when_pinned(monkeypatch):
    # Pin configured but Slack response omits team → fail closed.
    provider = make_provider(team_id=PINNED)
    seed_pending(provider)

    class _Fake:
        def oauth_v2_access(self, **kwargs):
            return {"ok": True, "authed_user": {"access_token": "xoxp-secret", "id": "U1"}}

    monkeypatch.setattr(provider_mod, "WebClient", lambda *a, **k: _Fake())

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    assert "access_denied" in resp.body.decode()
    assert provider._slack_tokens == {}


def test_callback_allows_matching_email_domain(monkeypatch):
    provider = make_provider(team_id=PINNED, allowed_email_domains=["joinhandshake.com"])
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=PINNED, email="alice@joinhandshake.com")

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    code_keys = [k for k in provider._slack_tokens if k.startswith("code:")]
    assert len(code_keys) == 1


def test_callback_rejects_wrong_email_domain(monkeypatch):
    provider = make_provider(team_id=PINNED, allowed_email_domains=["joinhandshake.com"])
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=PINNED, email="fellow@gmail.com")

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    assert "access_denied" in resp.body.decode()
    assert provider._slack_tokens == {}


def test_callback_rejects_missing_email_when_gated(monkeypatch):
    provider = make_provider(team_id=PINNED, allowed_email_domains=["joinhandshake.com"])
    seed_pending(provider)
    patch_slack(monkeypatch, team_id=PINNED, email="")  # no email returned → fail closed

    resp = asyncio.run(provider._handle_slack_callback(make_request()))

    assert isinstance(resp, HTMLResponse)
    assert "access_denied" in resp.body.decode()
    assert provider._slack_tokens == {}
