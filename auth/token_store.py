"""
SQLite-backed persistence for OAuth state.

The OAuth provider keeps its dicts as the runtime source of truth and
mirrors every long-lived mutation here (write-through), hydrating from
this store once at startup. Without persistence, a server restart wipes
DCR client registrations — and the only client-side recovery in Claude
Code is removing the connector and re-adding it under a new name.

Values are encrypted with Fernet before hitting disk: client rows carry
client_secrets, refresh tokens are bearer secrets, and slack_token rows
hold xoxp-* user tokens. Row keys stay plaintext — Fernet is
non-deterministic, so encrypted keys couldn't support UPSERT/DELETE by
key. Raw MCP token strings therefore appear as keys; mitigated by the
1-hour access-token expiry and 0600 file permissions. If this ever moves
to a shared Postgres, hash the keys.
"""

import logging
import os
import sqlite3
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Row kinds. Transient state (auth codes, pending authorizations,
# code:-keyed slack tokens) is intentionally never persisted: a restart
# mid-flow just means redoing that OAuth flow.
KIND_CLIENT = "client"  # DCR registration JSON, keyed by client_id
KIND_ACCESS_TOKEN = "access_token"  # AccessToken JSON, keyed by token string
KIND_REFRESH_TOKEN = "refresh_token"  # RefreshToken JSON, keyed by token string
KIND_TOKEN_LINK = "token_link"  # access token -> refresh token string
KIND_SLACK_TOKEN = "slack_token"  # Slack xoxp info JSON, keyed by access token

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_state (
    tenant_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB NOT NULL,
    expires_at REAL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_oauth_state_expires ON oauth_state(expires_at);
"""

KEYGEN_HINT = (
    'python -c "from cryptography.fernet import Fernet; '
    'print(Fernet.generate_key().decode())"'
)


class TokenStore:
    """Thread-safe SQLite key-value store with Fernet-encrypted values.

    One instance is shared by every tenant provider; rows are namespaced
    by tenant_id. Writes happen only on OAuth lifecycle events (register,
    code exchange, refresh, revoke) — never per tool call — so a single
    connection guarded by a lock is plenty.
    """

    def __init__(self, db_path: str, encryption_key: str):
        # Fernet raises ValueError on a malformed key — fail fast at boot.
        self._fernet = Fernet(encryption_key)

        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)

        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA busy_timeout=5000")

        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        elif version > _SCHEMA_VERSION:
            raise RuntimeError(
                f"Database {db_path} has schema version {version}, newer than "
                f"this server supports ({_SCHEMA_VERSION}). Refusing to start."
            )

        os.chmod(db_path, 0o600)
        self.purge_expired()

    def put(
        self,
        tenant_id: str,
        kind: str,
        key: str,
        value: str,
        expires_at: float | None = None,
    ) -> None:
        encrypted = self._fernet.encrypt(value.encode())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO oauth_state (tenant_id, kind, key, value, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, kind, key)
                DO UPDATE SET value=excluded.value,
                              expires_at=excluded.expires_at,
                              updated_at=excluded.updated_at
                """,
                (tenant_id, kind, key, encrypted, expires_at, time.time()),
            )

    def get_all(self, tenant_id: str, kind: str) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, value FROM oauth_state WHERE tenant_id = ? AND kind = ?",
                (tenant_id, kind),
            ).fetchall()
        result = {}
        for key, encrypted in rows:
            try:
                result[key] = self._fernet.decrypt(encrypted).decode()
            except InvalidToken as exc:
                # Never silently drop rows: a wrong key would otherwise look
                # like an empty store and quietly log everyone out.
                raise RuntimeError(
                    "SLACK_MCP_ENCRYPTION_KEY does not match the existing "
                    f"database at {self.db_path} — refusing to start. "
                    "Restore the original key, or delete the database to "
                    "start fresh (users will need to re-authenticate)."
                ) from exc
        return result

    def delete(self, tenant_id: str, kind: str, key: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM oauth_state WHERE tenant_id = ? AND kind = ? AND key = ?",
                (tenant_id, kind, key),
            )

    def purge_expired(self) -> None:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM oauth_state WHERE expires_at IS NOT NULL AND expires_at < ?",
                (time.time(),),
            )
        if cursor.rowcount:
            logger.debug("Purged %d expired rows from %s", cursor.rowcount, self.db_path)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def create_token_store_from_env() -> TokenStore | None:
    """Build the shared TokenStore from environment configuration.

    SLACK_MCP_DB_PATH: database file path (default ./data/slack-mcp.db).
        Set to an empty string to disable persistence entirely.
    SLACK_MCP_ENCRYPTION_KEY: Fernet key, required when persistence is on.
    """
    db_path = os.getenv("SLACK_MCP_DB_PATH", "./data/slack-mcp.db")
    if not db_path:
        logger.warning(
            "SLACK_MCP_DB_PATH is empty — persistence disabled; all OAuth "
            "state will be lost on restart"
        )
        return None

    encryption_key = os.getenv("SLACK_MCP_ENCRYPTION_KEY")
    if not encryption_key:
        raise RuntimeError(
            "SLACK_MCP_ENCRYPTION_KEY is required when persistence is enabled "
            f"(SLACK_MCP_DB_PATH={db_path!r}). Generate one with:\n  {KEYGEN_HINT}\n"
            "Or set SLACK_MCP_DB_PATH to an empty string to disable persistence."
        )

    return TokenStore(db_path, encryption_key)
