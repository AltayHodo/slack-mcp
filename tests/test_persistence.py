"""
Tests for SQLite persistence of OAuth state.

Each "restart" is simulated by building a fresh TokenStore + provider on
the same database file and asserting the state a real MCP client depends
on (DCR registration, tokens, Slack token association) is restored.
"""

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest
from auth.slack_oauth_provider import SlackOAuthProvider
from auth.token_store import SqliteTokenStore, create_token_store_from_env
from cryptography.fernet import Fernet
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull

KEY = Fernet.generate_key().decode()
XOXP = "xoxp-secret-slack-token-123"
CLIENT_SECRET = "dcr-client-secret-456"


def make_store(tmp_path, key=KEY):
    return SqliteTokenStore(str(tmp_path / "state.db"), key)


def make_provider(store, tenant_id="t1"):
    return SlackOAuthProvider(
        slack_client_id="slack-app-id",
        slack_client_secret="slack-app-secret",
        slack_redirect_uri="http://localhost:8001/oauth2callback",
        slack_scopes=["search:read"],
        tenant_id=tenant_id,
        token_store=store,
    )


def make_client(client_id="client-1"):
    return OAuthClientInformationFull(
        client_id=client_id,
        client_secret=CLIENT_SECRET,
        redirect_uris=["http://localhost:9000/callback"],
    )


def issue_tokens(provider, client):
    """Run the MCP code exchange the way the real flow reaches it."""
    asyncio.run(provider.register_client(client))
    code = "mcp_auth_testcode"
    provider.auth_codes[code] = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri="http://localhost:9000/callback",
        redirect_uri_provided_explicitly=True,
        scopes=["search:read"],
        expires_at=time.time() + 300,
        code_challenge="challenge",
    )
    provider._slack_tokens[f"code:{code}"] = {
        "token": XOXP,
        "user_id": "U123",
        "created_at": time.time(),
    }
    return asyncio.run(provider.exchange_authorization_code(client, provider.auth_codes[code]))


def db_rows(tmp_path, kind=None):
    conn = sqlite3.connect(str(tmp_path / "state.db"))
    if kind:
        rows = conn.execute(
            "SELECT key FROM oauth_state WHERE kind = ?", (kind,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT kind, key FROM oauth_state").fetchall()
    conn.close()
    return rows


def test_client_registration_survives_restart(tmp_path):
    provider = make_provider(make_store(tmp_path))
    client = make_client()
    asyncio.run(provider.register_client(client))

    restarted = make_provider(make_store(tmp_path))
    restored = asyncio.run(restarted.get_client("client-1"))
    assert restored is not None
    assert restored.client_id == "client-1"
    assert restored.client_secret == CLIENT_SECRET
    assert [str(u) for u in restored.redirect_uris] == ["http://localhost:9000/callback"]


def test_tokens_and_slack_token_survive_restart(tmp_path):
    provider = make_provider(make_store(tmp_path))
    client = make_client()
    oauth_token = issue_tokens(provider, client)

    restarted = make_provider(make_store(tmp_path))
    assert oauth_token.access_token in restarted.access_tokens
    assert oauth_token.refresh_token in restarted.refresh_tokens
    assert restarted._refresh_to_access_map[oauth_token.refresh_token] == oauth_token.access_token
    assert restarted._access_to_refresh_map[oauth_token.access_token] == oauth_token.refresh_token

    loaded = asyncio.run(restarted.load_access_token(oauth_token.access_token))
    assert loaded is not None
    assert loaded.claims["slack_token"] == XOXP
    assert loaded.claims["slack_user_id"] == "U123"


def test_refresh_after_restart(tmp_path):
    provider = make_provider(make_store(tmp_path))
    client = make_client()
    oauth_token = issue_tokens(provider, client)

    restarted = make_provider(make_store(tmp_path))
    refresh_obj = restarted.refresh_tokens[oauth_token.refresh_token]
    new_token = asyncio.run(
        restarted.exchange_refresh_token(client, refresh_obj, ["search:read"])
    )

    # Slack token followed the rotation; old rows are gone from the DB.
    loaded = asyncio.run(restarted.load_access_token(new_token.access_token))
    assert loaded.claims["slack_token"] == XOXP
    persisted_keys = {key for (key,) in db_rows(tmp_path, "access_token")}
    assert persisted_keys == {new_token.access_token}
    persisted_refresh = {key for (key,) in db_rows(tmp_path, "refresh_token")}
    assert persisted_refresh == {new_token.refresh_token}

    # And the rotated state itself survives another restart.
    restarted_again = make_provider(make_store(tmp_path))
    loaded = asyncio.run(restarted_again.load_access_token(new_token.access_token))
    assert loaded.claims["slack_token"] == XOXP


def test_secrets_encrypted_on_disk(tmp_path):
    provider = make_provider(make_store(tmp_path))
    issue_tokens(provider, make_client())

    raw = Path(tmp_path / "state.db").read_bytes()
    assert b"xoxp-" not in raw
    assert CLIENT_SECRET.encode() not in raw


def test_revocation_and_pruning_delete_rows(tmp_path):
    provider = make_provider(make_store(tmp_path))
    oauth_token = issue_tokens(provider, make_client())

    access_obj = provider.access_tokens[oauth_token.access_token]
    asyncio.run(provider.revoke_token(access_obj))
    assert db_rows(tmp_path, "access_token") == []
    assert db_rows(tmp_path, "refresh_token") == []
    assert db_rows(tmp_path, "token_link") == []

    # Slack token row lingers until pruning (mirrors in-memory semantics).
    assert db_rows(tmp_path, "slack_token") != []
    provider._cleanup_expired()
    assert db_rows(tmp_path, "slack_token") == []


def test_expired_access_purged_on_boot_but_refresh_path_intact(tmp_path):
    store = make_store(tmp_path)
    provider = make_provider(store)
    client = make_client()
    oauth_token = issue_tokens(provider, client)

    # Rewrite the access-token row as already expired (simulates restarting
    # after the 1h expiry has passed).
    access_obj = provider.access_tokens[oauth_token.access_token]
    expired = access_obj.model_copy(update={"expires_at": int(time.time()) - 10})
    store.put("t1", "access_token", expired.token, expired.model_dump_json(), expired.expires_at)

    restarted = make_provider(make_store(tmp_path))
    assert oauth_token.access_token not in restarted.access_tokens
    assert db_rows(tmp_path, "access_token") == []

    # Refresh still works: link map and Slack token were retained.
    refresh_obj = restarted.refresh_tokens[oauth_token.refresh_token]
    new_token = asyncio.run(
        restarted.exchange_refresh_token(client, refresh_obj, ["search:read"])
    )
    loaded = asyncio.run(restarted.load_access_token(new_token.access_token))
    assert loaded.claims["slack_token"] == XOXP


def test_missing_key_fails_fast(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_MCP_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SLACK_MCP_DB_PATH", str(tmp_path / "state.db"))
    monkeypatch.delenv("SLACK_MCP_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SLACK_MCP_ENCRYPTION_KEY"):
        create_token_store_from_env()


def test_empty_db_path_disables_persistence(monkeypatch):
    monkeypatch.delenv("SLACK_MCP_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SLACK_MCP_DB_PATH", "")
    assert create_token_store_from_env() is None


def test_wrong_key_fails_fast(tmp_path):
    provider = make_provider(make_store(tmp_path))
    asyncio.run(provider.register_client(make_client()))

    other_key = Fernet.generate_key().decode()
    with pytest.raises(RuntimeError, match="does not match"):
        make_provider(make_store(tmp_path, key=other_key))


def test_tenant_isolation(tmp_path):
    store = make_store(tmp_path)
    provider_a = make_provider(store, tenant_id="a")
    asyncio.run(provider_a.register_client(make_client("client-a")))

    restarted_store = make_store(tmp_path)
    restarted_a = make_provider(restarted_store, tenant_id="a")
    restarted_b = make_provider(restarted_store, tenant_id="b")
    assert asyncio.run(restarted_a.get_client("client-a")) is not None
    assert asyncio.run(restarted_b.get_client("client-a")) is None


def test_no_store_is_noop(tmp_path):
    provider = make_provider(None)
    oauth_token = issue_tokens(provider, make_client())
    loaded = asyncio.run(provider.load_access_token(oauth_token.access_token))
    assert loaded.claims["slack_token"] == XOXP
    assert not (tmp_path / "state.db").exists()
