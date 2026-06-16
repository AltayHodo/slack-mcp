"""
Backend-contract tests for TokenStore.

The same assertions run against both backends so SqliteTokenStore and
PostgresTokenStore are verified to behave identically. The Postgres backend is
exercised only when TEST_DATABASE_URL is set (CI can provide a service);
otherwise those parametrizations are skipped. Each Postgres test uses a unique
tenant_id prefix so a shared database doesn't cross-contaminate.
"""

import os
import uuid

import pytest
from auth.token_store import (
    KIND_CLIENT,
    KIND_SLACK_TOKEN,
    PostgresTokenStore,
    SqliteTokenStore,
)
from cryptography.fernet import Fernet

KEY = Fernet.generate_key().decode()
PG_URL = os.getenv("TEST_DATABASE_URL")

_have_pg = PG_URL is not None
pg_param = pytest.param(
    "postgres",
    marks=pytest.mark.skipif(not _have_pg, reason="TEST_DATABASE_URL not set"),
)


@pytest.fixture(params=["sqlite", pg_param])
def store(request, tmp_path):
    """Yield a fresh store for each backend; clean up after."""
    if request.param == "sqlite":
        s = SqliteTokenStore(str(tmp_path / "state.db"), KEY)
    else:
        s = PostgresTokenStore(PG_URL, KEY)
    yield s
    s.close()


# Unique per test run so a shared Postgres DB never collides across runs.
def tid(suffix=""):
    return f"t-{uuid.uuid4().hex[:8]}{suffix}"


def test_put_get_roundtrip(store):
    t = tid()
    store.put(t, KIND_CLIENT, "client-1", '{"client_id": "client-1"}')
    got = store.get_all(t, KIND_CLIENT)
    assert got == {"client-1": '{"client_id": "client-1"}'}


def test_upsert_replaces_value(store):
    t = tid()
    store.put(t, KIND_CLIENT, "c", "v1")
    store.put(t, KIND_CLIENT, "c", "v2")
    assert store.get_all(t, KIND_CLIENT) == {"c": "v2"}


def test_delete(store):
    t = tid()
    store.put(t, KIND_CLIENT, "c", "v")
    store.delete(t, KIND_CLIENT, "c")
    assert store.get_all(t, KIND_CLIENT) == {}


def test_tenant_isolation(store):
    a, b = tid("-a"), tid("-b")
    store.put(a, KIND_CLIENT, "c", "from-a")
    assert store.get_all(b, KIND_CLIENT) == {}
    assert store.get_all(a, KIND_CLIENT) == {"c": "from-a"}


def test_kind_isolation(store):
    t = tid()
    store.put(t, KIND_CLIENT, "k", "client-val")
    store.put(t, KIND_SLACK_TOKEN, "k", "slack-val")
    assert store.get_all(t, KIND_CLIENT) == {"k": "client-val"}
    assert store.get_all(t, KIND_SLACK_TOKEN) == {"k": "slack-val"}


def test_purge_expired(store):
    t = tid()
    store.put(t, KIND_CLIENT, "live", "v", expires_at=None)
    store.put(t, KIND_CLIENT, "stale", "v", expires_at=1.0)  # far in the past
    store.purge_expired()
    assert set(store.get_all(t, KIND_CLIENT)) == {"live"}


def test_value_encrypted_not_plaintext(store):
    t = tid()
    secret = "xoxp-super-secret-token"
    store.put(t, KIND_SLACK_TOKEN, "k", secret)
    # Read the raw stored bytes back out of the backend and confirm the
    # plaintext secret never appears.
    rows = list(store._select_all(t, KIND_SLACK_TOKEN))
    assert rows, "expected a stored row"
    raw = bytes(rows[0][1])
    assert secret.encode() not in raw
    # But it round-trips through the encrypted API.
    assert store.get_all(t, KIND_SLACK_TOKEN)["k"] == secret


def test_wrong_key_raises(store, tmp_path):
    t = tid()
    store.put(t, KIND_CLIENT, "c", "v")

    other_key = Fernet.generate_key().decode()
    if isinstance(store, SqliteTokenStore):
        reopened = SqliteTokenStore(store.db_path, other_key)
    else:
        reopened = PostgresTokenStore(PG_URL, other_key)
    try:
        with pytest.raises(RuntimeError, match="does not match"):
            reopened.get_all(t, KIND_CLIENT)
    finally:
        reopened.close()
