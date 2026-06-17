"""
Tests for the encryption Cipher abstraction and env-based selection.

FernetCipher is exercised directly. KmsCipher is exercised against a fake KMS
client (no real GCP needed) — its job is just to call KMS encrypt/decrypt and
map failures to DecryptionError; the real KMS round-trip is validated in the
GCP environment.
"""

import pytest
from auth.token_store import (
    DecryptionError,
    FernetCipher,
    KmsCipher,
    create_cipher_from_env,
)
from cryptography.fernet import Fernet


def test_fernet_roundtrip():
    c = FernetCipher(Fernet.generate_key().decode())
    assert c.decrypt(c.encrypt(b"hello world")) == b"hello world"


def test_fernet_wrong_key_raises_decryption_error():
    blob = FernetCipher(Fernet.generate_key().decode()).encrypt(b"secret")
    other = FernetCipher(Fernet.generate_key().decode())
    with pytest.raises(DecryptionError):
        other.decrypt(blob)


class _FakeKmsClient:
    """Trivial reversible 'KMS': prefixes a marker; rejects anything without it."""

    MARK = b"KMS::"

    def __init__(self, *a, **k):
        pass

    def encrypt(self, request):
        return type("R", (), {"ciphertext": self.MARK + request["plaintext"]})

    def decrypt(self, request):
        ct = request["ciphertext"]
        if not ct.startswith(self.MARK):
            raise ValueError("not valid KMS ciphertext")
        return type("R", (), {"plaintext": ct[len(self.MARK):]})


@pytest.fixture
def fake_kms(monkeypatch):
    from google.cloud import kms

    monkeypatch.setattr(kms, "KeyManagementServiceClient", _FakeKmsClient)


KEY_NAME = "projects/p/locations/l/keyRings/r/cryptoKeys/k"


def test_kms_roundtrip(fake_kms):
    c = KmsCipher(KEY_NAME)
    assert c.decrypt(c.encrypt(b"hello")) == b"hello"


def test_kms_decrypt_failure_raises_decryption_error(fake_kms):
    c = KmsCipher(KEY_NAME)
    with pytest.raises(DecryptionError):
        c.decrypt(b"not-kms-ciphertext")


def test_create_cipher_selects_kms(monkeypatch, fake_kms):
    monkeypatch.setenv("SLACK_MCP_KMS_KEY", KEY_NAME)
    assert isinstance(create_cipher_from_env(), KmsCipher)


def test_create_cipher_selects_fernet(monkeypatch):
    monkeypatch.delenv("SLACK_MCP_KMS_KEY", raising=False)
    monkeypatch.setenv("SLACK_MCP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    assert isinstance(create_cipher_from_env(), FernetCipher)


def test_create_cipher_kms_takes_precedence(monkeypatch, fake_kms):
    monkeypatch.setenv("SLACK_MCP_KMS_KEY", KEY_NAME)
    monkeypatch.setenv("SLACK_MCP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    assert isinstance(create_cipher_from_env(), KmsCipher)


def test_create_cipher_requires_a_key(monkeypatch):
    monkeypatch.delenv("SLACK_MCP_KMS_KEY", raising=False)
    monkeypatch.delenv("SLACK_MCP_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_cipher_from_env()
