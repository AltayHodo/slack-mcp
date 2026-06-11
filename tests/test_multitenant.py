"""
Tests for multi-tenant OAuth configuration and app composition.
"""

import json

import pytest
from auth.oauth_config import SlackOAuthConfig, load_tenants


def test_path_prefix_and_mcp_path():
    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="duolingo")
    assert cfg.path_prefix == "/duolingo"
    assert cfg.mcp_path == "/duolingo/mcp"


def test_legacy_empty_tenant_has_no_prefix():
    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="")
    assert cfg.path_prefix == ""
    assert cfg.mcp_path == "/mcp"


def test_tenant_id_strips_slashes():
    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="/duo/")
    assert cfg.tenant_id == "duo"
    assert cfg.path_prefix == "/duo"


def test_oauth_urls_are_prefixed_with_external_url():
    cfg = SlackOAuthConfig(
        client_id="x",
        client_secret="y",
        tenant_id="handshake",
        external_url="https://mcp.example.com",
    )
    assert cfg.get_oauth_base_url() == "https://mcp.example.com/handshake"
    assert cfg.get_slack_callback_url() == "https://mcp.example.com/handshake/oauth2callback"


def test_external_url_explicit_none_overrides_env(monkeypatch):
    monkeypatch.setenv("SLACK_EXTERNAL_URL", "https://from-env.example")
    cfg = SlackOAuthConfig(
        client_id="x",
        client_secret="y",
        tenant_id="t",
        base_uri="http://localhost",
        port=8001,
        external_url=None,
    )
    # Explicit None must not pick up the env var; falls back to host base_url.
    assert cfg.get_oauth_base_url() == "http://localhost:8001/t"


def test_team_id_passthrough():
    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="t", team_id="T_ABC")
    assert cfg.team_id == "T_ABC"


def test_load_tenants_from_json(monkeypatch):
    monkeypatch.setenv("SLACK_EXTERNAL_URL", "https://mcp.example.com")
    monkeypatch.setenv(
        "SLACK_TENANTS",
        json.dumps(
            [
                {"id": "duolingo", "client_id": "a", "client_secret": "sa", "team_id": "T_A"},
                {"id": "handshake", "client_id": "b", "client_secret": "sb", "team_id": "T_B"},
            ]
        ),
    )
    tenants = load_tenants()
    assert len(tenants) == 2
    by_id = {t.tenant_id: t for t in tenants}
    assert by_id["duolingo"].get_slack_callback_url() == "https://mcp.example.com/duolingo/oauth2callback"
    assert by_id["handshake"].team_id == "T_B"
    assert all(t.is_configured() for t in tenants)


def test_load_tenants_secret_from_env_indirection(monkeypatch):
    monkeypatch.setenv("WS_SECRET", "super-secret")
    monkeypatch.setenv(
        "SLACK_TENANTS",
        json.dumps([{"id": "t", "client_id": "a", "client_secret_env": "WS_SECRET"}]),
    )
    tenants = load_tenants()
    assert tenants[0].client_secret == "super-secret"


def test_load_tenants_rejects_duplicate_ids(monkeypatch):
    monkeypatch.setenv(
        "SLACK_TENANTS",
        json.dumps([{"id": "t", "client_id": "a", "client_secret": "s"},
                    {"id": "t", "client_id": "b", "client_secret": "s"}]),
    )
    with pytest.raises(ValueError, match="Duplicate tenant id"):
        load_tenants()


def test_load_tenants_rejects_missing_id(monkeypatch):
    monkeypatch.setenv("SLACK_TENANTS", json.dumps([{"client_id": "a", "client_secret": "s"}]))
    with pytest.raises(ValueError, match="non-empty 'id'"):
        load_tenants()


def test_load_tenants_legacy_single_tenant(monkeypatch):
    monkeypatch.delenv("SLACK_TENANTS", raising=False)
    monkeypatch.setenv("SLACK_CLIENT_ID", "legacy_id")
    monkeypatch.setenv("SLACK_CLIENT_SECRET", "legacy_secret")
    tenants = load_tenants()
    assert len(tenants) == 1
    assert tenants[0].tenant_id == ""
    assert tenants[0].path_prefix == ""
    assert tenants[0].is_configured()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
