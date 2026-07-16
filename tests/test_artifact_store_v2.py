"""
tests/test_artifact_store_v2.py
================================
ArtifactStore v2: envelopes with store key cruda and conversion v1v2.
"""
from __future__ import annotations

import secrets as _secrets

import pytest

from legacy.vault.artifact_store import (
    ArtifactStore,
    STORE_MAGIC,
    STORE_MAGIC_V2,
)
from legacy.vault.locker import VaultAuthError

PASS = "a-passphrase"
KEY = _secrets.token_bytes(32)


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "artifacts")


# V2 artifact-store behavior.

def test_v2_roundtrip(store):
    data = b"content encrypted with key cruda \x00\xff"
    h = store.put_bytes(data, KEY)
    assert store.envelope_version(h) == "2"
    assert store._path_for(h).read_bytes().startswith(STORE_MAGIC_V2)
    assert store.get(h, KEY) == data


def test_v2_wrong_key_raises(store):
    h = store.put_bytes(b"data", KEY)
    with pytest.raises(VaultAuthError):
        store.get(h, _secrets.token_bytes(32))


def test_v2_rejects_passphrase_and_v1_rejects_key(store):
    """the tipo of the secreto must corresponder to the envelope  errores claros,
    nunca decrypted accidental."""
    h2 = store.put_bytes(b"with key", KEY)
    h1 = store.put_bytes(b"with passphrase", PASS)

    assert store.envelope_version(h1) == "1"
    with pytest.raises(VaultAuthError, match="v2"):
        store.get(h2, PASS)                     # str contra envelope v2
    with pytest.raises(VaultAuthError, match="v1"):
        store.get(h1, KEY)                      # bytes contra envelope v1


def test_v2_key_must_be_32_bytes(store):
    with pytest.raises(VaultAuthError):
        store.put_bytes(b"data", b"key-corta")


def test_v2_tamper_detected(store):
    h = store.put_bytes(b"content original", KEY)
    p = store._path_for(h)
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 0xFF
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultAuthError):
        store.get(h, KEY)


def test_v2_envelope_cannot_be_renamed(store):
    """the AAD (id) sigue aplicando in v2."""
    import hashlib
    ha = store.put_bytes(b"artifact A", KEY)
    hb = hashlib.sha256(b"artifact B").hexdigest()
    pb = store._path_for(hb)
    pb.parent.mkdir(parents=True, exist_ok=True)
    pb.write_bytes(store._path_for(ha).read_bytes())
    with pytest.raises(VaultAuthError):
        store.get(hb, KEY)


# Multiple artifacts remain independently restorable.

def test_convert_to_key(store):
    h1 = store.put_bytes(b"document one", PASS)
    h2 = store.put_bytes(b"document two", PASS)

    stats = store.convert_to_key(PASS, KEY)
    assert stats == {"converted": 2, "skipped": 0}
    for h, expected in [(h1, b"document one"), (h2, b"document two")]:
        assert store.envelope_version(h) == "2"
        assert store.get(h, KEY) == expected
        assert not store.verify(h, PASS)        # the passphrase already no decrypts


def test_convert_is_rerunnable(store):
    store.put_bytes(b"one", PASS)
    store.put_bytes(b"dos", KEY)                # already v2
    stats = store.convert_to_key(PASS, KEY)
    assert stats == {"converted": 1, "skipped": 1}
    stats2 = store.convert_to_key(PASS, KEY)    # segunda corrida: no-op
    assert stats2 == {"converted": 0, "skipped": 2}


def test_convert_aborts_on_wrong_passphrase(store):
    h = store.put_bytes(b"document", PASS)
    with pytest.raises(VaultAuthError):
        store.convert_to_key("incorrect", KEY)
    assert store.envelope_version(h) == "1"     # nada cambio


# V2 migration and key handling.

def test_rekey_skips_v2_envelopes(store):
    h1 = store.put_bytes(b"old v1", PASS)
    h2 = store.put_bytes(b"new v2", KEY)
    stats = store.rekey(PASS, "another-passphrase")
    assert stats == {"rotated": 1, "skipped": 1}
    assert store.get(h1, "another-passphrase") == b"old v1"
    assert store.get(h2, KEY) == b"new v2"    # v2 intacto
