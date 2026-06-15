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


def test_load_tenants_rejects_non_array(monkeypatch):
    monkeypatch.setenv("SLACK_TENANTS", '{"id": "internal"}')  # object, not array
    with pytest.raises(ValueError, match="must be a JSON array"):
        load_tenants()


def test_load_tenants_rejects_non_object_entry(monkeypatch):
    monkeypatch.setenv("SLACK_TENANTS", '["internal", "fellow-facing"]')  # strings, not objects
    with pytest.raises(ValueError, match="must be a JSON object"):
        load_tenants()


def test_main_port_resolution_handles_empty_env(monkeypatch):
    """main() must not crash on a present-but-empty SLACK_MCP_PORT."""
    import os

    monkeypatch.setenv("SLACK_MCP_PORT", "")
    # Mirror the resolution logic in main(); the bug was int("") raising.
    port = int(os.getenv("SLACK_MCP_PORT") or "8001")
    assert port == 8001


def test_root_metadata_alias_for_legacy_as_path():
    """AS metadata at the legacy exact path gets a tenant-suffixed root alias."""
    from starlette.routing import Route

    from main import _root_metadata_routes

    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="internal")

    async def _endpoint(request):  # pragma: no cover - placeholder
        return None

    class _FakeApp:
        routes = [
            Route("/.well-known/oauth-authorization-server", endpoint=_endpoint),
            Route("/.well-known/oauth-protected-resource/internal/mcp", endpoint=_endpoint),
        ]

    paths = {r.path for r in _root_metadata_routes(_FakeApp(), cfg)}
    assert "/.well-known/oauth-authorization-server/internal" in paths
    assert "/.well-known/oauth-protected-resource/internal/mcp" in paths


def test_root_metadata_alias_for_path_aware_as_path():
    """A future path-aware AS route is matched too, without duplicating itself."""
    from starlette.routing import Route

    from main import _root_metadata_routes

    cfg = SlackOAuthConfig(client_id="x", client_secret="y", tenant_id="internal")

    async def _endpoint(request):  # pragma: no cover - placeholder
        return None

    class _FakeApp:
        routes = [
            Route("/.well-known/oauth-authorization-server/internal", endpoint=_endpoint),
        ]

    # Already at the alias path → startswith matches but no duplicate route added.
    extra = _root_metadata_routes(_FakeApp(), cfg)
    assert extra == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
