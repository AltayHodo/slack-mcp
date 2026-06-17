"""
Persistence for OAuth state, behind a backend-agnostic interface.

The OAuth provider keeps its dicts as the runtime source of truth and mirrors
every long-lived mutation here (write-through), hydrating from this store once
at startup. Without persistence, a server restart wipes DCR client
registrations — and the only client-side recovery in Claude Code is removing
the connector and re-adding it under a new name.

Two backends implement the same contract:
  - SqliteTokenStore   — a local file; zero dependencies, used for local dev
                         and tests.
  - PostgresTokenStore — a managed database (e.g. GCP Cloud SQL); used in
                         production, where the container is disposable and
                         state must live outside it.

Values are encrypted with Fernet before they hit the backend: client rows
carry client_secrets, refresh tokens are bearer secrets, and slack_token rows
hold xoxp-* user tokens. Row keys stay plaintext — Fernet is non-deterministic,
so encrypted keys couldn't support UPSERT/DELETE by key. Raw MCP token strings
therefore appear as keys; mitigated by the 1-hour access-token expiry (and, for
SQLite, 0600 file permissions). For Postgres, key hashing is a possible future
hardening.
"""

import abc
import logging
import os
import sqlite3
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Row kinds. Transient state (auth codes, pending authorizations, code:-keyed
# slack tokens) is intentionally never persisted: a restart mid-flow just means
# redoing that OAuth flow.
KIND_CLIENT = "client"  # DCR registration JSON, keyed by client_id
KIND_ACCESS_TOKEN = "access_token"  # AccessToken JSON, keyed by token string
KIND_REFRESH_TOKEN = "refresh_token"  # RefreshToken JSON, keyed by token string
KIND_TOKEN_LINK = "token_link"  # access token -> refresh token string
KIND_SLACK_TOKEN = "slack_token"  # Slack xoxp info JSON, keyed by access token

KEYGEN_HINT = (
    'python -c "from cryptography.fernet import Fernet; '
    'print(Fernet.generate_key().decode())"'
)

_WRONG_KEY_MSG = (
    "Stored OAuth state at {label} could not be decrypted with the configured "
    "key — refusing to start. The encryption key (SLACK_MCP_ENCRYPTION_KEY) or "
    "KMS key (SLACK_MCP_KMS_KEY) may have changed. Restore the original, or wipe "
    "the persisted state to start fresh (users will need to re-authenticate)."
)


class DecryptionError(Exception):
    """Raised by a Cipher when ciphertext can't be decrypted (e.g. wrong key)."""


class Cipher(abc.ABC):
    """Encrypts/decrypts the value blobs stored by TokenStore.

    Two implementations: FernetCipher (local/dev/tests, key in env) and
    KmsCipher (production, key managed by Google Cloud KMS so it never enters
    the app). Selected by environment in create_token_store_from_env.
    """

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes: ...

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return plaintext, or raise DecryptionError if it can't be decrypted."""


class FernetCipher(Cipher):
    def __init__(self, encryption_key: str):
        # Fernet raises ValueError on a malformed key — fail fast at boot.
        self._fernet = Fernet(encryption_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            raise DecryptionError from exc


class KmsCipher(Cipher):
    """Envelope-free symmetric encryption via a Google Cloud KMS crypto key.

    Each value is encrypted/decrypted by a KMS API call. Suitable here because
    writes are low-volume (OAuth lifecycle events, not per request) and values
    are well under the KMS 64 KiB limit. The key material never leaves KMS;
    the app only holds the key's resource name and IAM permission to use it.
    """

    def __init__(self, key_name: str):
        # Lazy import so SQLite/Fernet-only environments don't need the dep.
        from google.cloud import kms

        self._key_name = key_name
        self._client = kms.KeyManagementServiceClient()

    def encrypt(self, plaintext: bytes) -> bytes:
        resp = self._client.encrypt(request={"name": self._key_name, "plaintext": plaintext})
        return resp.ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            resp = self._client.decrypt(
                request={"name": self._key_name, "ciphertext": ciphertext}
            )
            return resp.plaintext
        except Exception as exc:  # GoogleAPIError, wrong key, malformed, etc.
            raise DecryptionError from exc


class TokenStore(abc.ABC):
    """Encrypted key-value store for OAuth state.

    The base class owns encryption (via an injected Cipher) and the public API;
    subclasses implement the four low-level row operations against a concrete
    backend. One instance is shared by every tenant provider; rows are
    namespaced by tenant_id. Writes happen only on OAuth lifecycle events
    (register, code exchange, refresh, revoke) — never per tool call.
    """

    def __init__(self, cipher: Cipher):
        self._cipher = cipher

    @property
    @abc.abstractmethod
    def label(self) -> str:
        """Human-readable backend identifier for logs (no secrets)."""

    def put(
        self,
        tenant_id: str,
        kind: str,
        key: str,
        value: str,
        expires_at: float | None = None,
    ) -> None:
        self._upsert(tenant_id, kind, key, self._cipher.encrypt(value.encode()), expires_at)

    def get_all(self, tenant_id: str, kind: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, encrypted in self._select_all(tenant_id, kind):
            try:
                result[key] = self._cipher.decrypt(bytes(encrypted)).decode()
            except DecryptionError as exc:
                # Never silently drop rows: a wrong key would otherwise look
                # like an empty store and quietly log everyone out.
                raise RuntimeError(_WRONG_KEY_MSG.format(label=self.label)) from exc
        return result

    def delete(self, tenant_id: str, kind: str, key: str) -> None:
        self._delete_row(tenant_id, kind, key)

    def purge_expired(self) -> None:
        self._purge_expired_rows(time.time())

    # ----- backend operations (subclass-provided) -------------------------

    @abc.abstractmethod
    def _upsert(
        self, tenant_id: str, kind: str, key: str, value: bytes, expires_at: float | None
    ) -> None: ...

    @abc.abstractmethod
    def _select_all(self, tenant_id: str, kind: str):
        """Return an iterable of (key, value_bytes) rows."""

    @abc.abstractmethod
    def _delete_row(self, tenant_id: str, kind: str, key: str) -> None: ...

    @abc.abstractmethod
    def _purge_expired_rows(self, now: float) -> None: ...

    @abc.abstractmethod
    def close(self) -> None: ...


_SQLITE_SCHEMA = """
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

_SQLITE_SCHEMA_VERSION = 1


class SqliteTokenStore(TokenStore):
    """File-backed store for local development and tests."""

    def __init__(self, db_path: str, cipher: Cipher):
        super().__init__(cipher)

        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)

        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA busy_timeout=5000")

        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self._conn.executescript(_SQLITE_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION}")
        elif version > _SQLITE_SCHEMA_VERSION:
            raise RuntimeError(
                f"Database {db_path} has schema version {version}, newer than "
                f"this server supports ({_SQLITE_SCHEMA_VERSION}). Refusing to start."
            )

        os.chmod(db_path, 0o600)
        self.purge_expired()

    @property
    def label(self) -> str:
        return f"sqlite:{self.db_path}"

    def _upsert(self, tenant_id, kind, key, value, expires_at):
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
                (tenant_id, kind, key, sqlite3.Binary(value), expires_at, time.time()),
            )

    def _select_all(self, tenant_id, kind):
        with self._lock:
            return self._conn.execute(
                "SELECT key, value FROM oauth_state WHERE tenant_id = ? AND kind = ?",
                (tenant_id, kind),
            ).fetchall()

    def _delete_row(self, tenant_id, kind, key):
        with self._lock:
            self._conn.execute(
                "DELETE FROM oauth_state WHERE tenant_id = ? AND kind = ? AND key = ?",
                (tenant_id, kind, key),
            )

    def _purge_expired_rows(self, now):
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM oauth_state WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
        if cursor.rowcount:
            logger.debug("Purged %d expired rows from %s", cursor.rowcount, self.db_path)

    def close(self):
        with self._lock:
            self._conn.close()


_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_state (
    tenant_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BYTEA NOT NULL,
    expires_at DOUBLE PRECISION,
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_oauth_state_expires ON oauth_state(expires_at);
"""


class PostgresTokenStore(TokenStore):
    """Managed-Postgres-backed store for production (e.g. GCP Cloud SQL).

    Connects via a standard libpq connection string. In a Cloud SQL
    deployment the connection typically goes through the Cloud SQL Auth
    Proxy/sidecar, so the app just needs a normal DSN pointing at it.
    """

    def __init__(self, conninfo: str, cipher: Cipher):
        super().__init__(cipher)

        # Imported lazily so SQLite-only environments don't need psycopg.
        from psycopg_pool import ConnectionPool

        self._conninfo = conninfo
        self._label = _sanitize_dsn(conninfo)
        # autocommit: each statement commits on its own — matches the simple,
        # low-volume write pattern and avoids leaving transactions open across
        # the OAuth handlers.
        self._pool = ConnectionPool(
            conninfo, min_size=1, max_size=4, kwargs={"autocommit": True}, open=False
        )
        self._pool.open()
        with self._pool.connection() as conn:
            conn.execute(_PG_SCHEMA)
        self.purge_expired()

    @property
    def label(self) -> str:
        return self._label

    def _upsert(self, tenant_id, kind, key, value, expires_at):
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO oauth_state (tenant_id, kind, key, value, expires_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, kind, key)
                DO UPDATE SET value=EXCLUDED.value,
                              expires_at=EXCLUDED.expires_at,
                              updated_at=EXCLUDED.updated_at
                """,
                (tenant_id, kind, key, value, expires_at, time.time()),
            )

    def _select_all(self, tenant_id, kind):
        with self._pool.connection() as conn:
            return conn.execute(
                "SELECT key, value FROM oauth_state WHERE tenant_id = %s AND kind = %s",
                (tenant_id, kind),
            ).fetchall()

    def _delete_row(self, tenant_id, kind, key):
        with self._pool.connection() as conn:
            conn.execute(
                "DELETE FROM oauth_state WHERE tenant_id = %s AND kind = %s AND key = %s",
                (tenant_id, kind, key),
            )

    def _purge_expired_rows(self, now):
        with self._pool.connection() as conn:
            conn.execute(
                "DELETE FROM oauth_state WHERE expires_at IS NOT NULL AND expires_at < %s",
                (now,),
            )

    def close(self):
        self._pool.close()


def _sanitize_dsn(conninfo: str) -> str:
    """Build a password-free label from a libpq DSN for logging."""
    try:
        from psycopg.conninfo import conninfo_to_dict

        d = conninfo_to_dict(conninfo)
        host = d.get("host", "?")
        port = d.get("port", "5432")
        dbname = d.get("dbname", "?")
        user = d.get("user", "")
        userpart = f"{user}@" if user else ""
        return f"postgresql://{userpart}{host}:{port}/{dbname}"
    except Exception:
        return "postgresql (configured)"


def create_cipher_from_env() -> Cipher:
    """Build the encryption Cipher from environment configuration.

    SLACK_MCP_KMS_KEY (a Cloud KMS crypto key resource name) selects KMS for
    production; otherwise SLACK_MCP_ENCRYPTION_KEY selects Fernet for local/dev.
    """
    kms_key = os.getenv("SLACK_MCP_KMS_KEY")
    if kms_key:
        return KmsCipher(kms_key)

    encryption_key = os.getenv("SLACK_MCP_ENCRYPTION_KEY")
    if encryption_key:
        return FernetCipher(encryption_key)

    raise RuntimeError(
        "Persistence is enabled but no encryption key is configured. Set "
        "SLACK_MCP_KMS_KEY (production, Cloud KMS) or SLACK_MCP_ENCRYPTION_KEY "
        f"(local/dev — generate with:\n  {KEYGEN_HINT}\n). Or disable persistence "
        "by setting SLACK_MCP_DB_PATH to an empty string with no SLACK_MCP_DATABASE_URL."
    )


def create_token_store_from_env() -> TokenStore | None:
    """Build the shared TokenStore from environment configuration.

    Backend selection:
      - SLACK_MCP_DATABASE_URL (or DATABASE_URL) set  -> PostgresTokenStore
      - else SLACK_MCP_DB_PATH non-empty (default     -> SqliteTokenStore
        ./data/slack-mcp.db)
      - else                                          -> persistence disabled

    Encryption (see create_cipher_from_env) is required whenever persistence is
    enabled: KMS in production, Fernet locally.
    """
    db_url = os.getenv("SLACK_MCP_DATABASE_URL") or os.getenv("DATABASE_URL")
    db_path = os.getenv("SLACK_MCP_DB_PATH", "./data/slack-mcp.db")

    if not db_url and not db_path:
        logger.warning(
            "No SLACK_MCP_DATABASE_URL and empty SLACK_MCP_DB_PATH — persistence "
            "disabled; all OAuth state will be lost on restart"
        )
        return None

    cipher = create_cipher_from_env()

    if db_url:
        return PostgresTokenStore(db_url, cipher)
    return SqliteTokenStore(db_path, cipher)
