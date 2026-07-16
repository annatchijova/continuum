"""
tests/test_vault_v2.py
=======================
Vault v2: keyslots, slot of recovery, rewrap and migracion v1v2.
"""
from __future__ import annotations

import hashlib
import json
import secrets as _secrets

import pytest

from legacy.vault.locker import (
    Vault,
    VaultAuthError,
    VaultCorruptError,
    _derive_key,
)

PASS = "passphrase-original"
NEW = "passphrase-new"
DATA = {"owner_id": "anna", "artifacts": [{"a": 1}], "notes": "  "}


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "t.vault")
    v.seal(DATA, PASS)
    return v


def _make_v1_envelope(path, data, passphrase):
    """Construye a vault v1 real (formato original) for tests of migracion."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plaintext = json.dumps(data, sort_keys=True, ensure_ascii=True).encode()
    salt = _secrets.token_bytes(32)
    nonce = _secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    path.write_text(json.dumps({
        "version": "1",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct_and_tag[:-16].hex(),
        "tag": ct_and_tag[-16:].hex(),
        "vault_hash": hashlib.sha256(plaintext).hexdigest(),
    }))


# Implementation note.
# Implementation note.
# Implementation note.

def test_new_vault_is_v2_with_passphrase_slot(vault, tmp_path):
    info = vault.info()
    assert info["version"] == "2"
    assert info["keyslots"] == ["passphrase"]
    assert not vault.has_recovery_slot()


def test_roundtrip_and_wrong_passphrase(vault):
    assert vault.open(PASS) == DATA
    with pytest.raises(VaultAuthError):
        vault.open("incorrect")


def test_seal_preserves_keyslots(vault):
    key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, key)
    vault.seal({"another": "content"}, PASS)      # re-sellado (lock/heartbeat)
    assert vault.has_recovery_slot()             # the custodia sobrevive
    assert vault.open_with_recovery(key) == {"another": "content"}


# Implementation note.
# Implementation note.
# Implementation note.

def test_recovery_slot_roundtrip(vault):
    key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, key)
    assert vault.open_with_recovery(key) == DATA
    with pytest.raises(VaultAuthError):
        vault.open_with_recovery(_secrets.token_bytes(32))


def test_add_recovery_requires_correct_passphrase(vault):
    with pytest.raises(VaultAuthError):
        vault.add_recovery_slot("incorrect", _secrets.token_bytes(32))


def test_replace_recovery_slot_invalidates_old_key(vault):
    old_key = _secrets.token_bytes(32)
    new_key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, old_key)
    vault.add_recovery_slot(PASS, new_key)       # replaces
    assert vault.open_with_recovery(new_key) == DATA
    with pytest.raises(VaultAuthError):
        vault.open_with_recovery(old_key)        # custodios old revocados


def test_remove_recovery_slot(vault):
    key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, key)
    assert vault.remove_recovery_slot(PASS) is True
    assert not vault.has_recovery_slot()
    with pytest.raises(VaultAuthError):
        vault.open_with_recovery(key)
    assert vault.remove_recovery_slot(PASS) is False


def test_recovery_key_must_be_32_bytes(vault):
    with pytest.raises(ValueError):
        vault.add_recovery_slot(PASS, b"corta")


# Implementation note.
# Implementation note.
# Implementation note.

def test_rewrap_rotates_passphrase_and_preserves_recovery(vault):
    key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, key)

    env_before = json.loads(vault._path.read_text())
    vault.rewrap_passphrase(PASS, NEW)
    env_after = json.loads(vault._path.read_text())

    # Implementation note.
    assert env_before["ciphertext"] == env_after["ciphertext"]
    assert vault.open(NEW) == DATA
    with pytest.raises(VaultAuthError):
        vault.open(PASS)
    # Implementation note.
    assert vault.open_with_recovery(key) == DATA


def test_rewrap_with_wrong_old_passphrase_fails(vault):
    with pytest.raises(VaultAuthError):
        vault.rewrap_passphrase("incorrect", NEW)
    assert vault.open(PASS) == DATA              # nada cambio


def test_set_passphrase_with_recovery(vault):
    """the camino of the heirs: reconstruyen the recovery key and fijan
    a passphrase new without conocer the old."""
    key = _secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, key)
    vault.set_passphrase_with_recovery(key, "passphrase-heredada")
    assert vault.open("passphrase-heredada") == DATA
    with pytest.raises(VaultAuthError):
        vault.open(PASS)                         # the old quedo reemplazada
    assert vault.has_recovery_slot()             # the custodia is conserva


# Implementation note.
# Implementation note.
# Implementation note.

def test_v1_envelope_still_opens(tmp_path):
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    v = Vault(path)
    assert v.info()["version"] == "1"
    assert v.open(PASS) == DATA


def test_seal_migrates_v1_to_v2(tmp_path):
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    v = Vault(path)
    data = v.open(PASS)
    v.seal(data, PASS)                           # primer re-sellado (lock)
    assert v.info()["version"] == "2"
    assert v.open(PASS) == DATA


def test_add_recovery_migrates_v1(tmp_path):
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    v = Vault(path)
    key = _secrets.token_bytes(32)
    v.add_recovery_slot(PASS, key)
    assert v.info()["version"] == "2"
    assert v.open_with_recovery(key) == DATA
    assert v.open(PASS) == DATA


def test_rewrap_migrates_v1(tmp_path):
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    v = Vault(path)
    v.rewrap_passphrase(PASS, NEW)
    assert v.info()["version"] == "2"
    assert v.open(NEW) == DATA
    with pytest.raises(VaultAuthError):
        v.open(PASS)


def test_recovery_on_v1_raises(tmp_path):
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    with pytest.raises(VaultAuthError, match="v1"):
        Vault(path).open_with_recovery(_secrets.token_bytes(32))


# Implementation note.
# Implementation note.
# Implementation note.

def test_tampered_payload_detected(vault):
    raw = json.loads(vault._path.read_text())
    raw["ciphertext"] = "deadbeef" * 8
    vault._path.write_text(json.dumps(raw))
    with pytest.raises((VaultAuthError, VaultCorruptError)):
        vault.open(PASS)


def test_foreign_keyslot_cannot_open_payload(tmp_path):
    """Trasplantar the keyslot of another vault (same passphrase) no opens the
    payload: each slot envuelve the data key of SU vault."""
    va = Vault(tmp_path / "a.vault"); va.seal({"v": "a"}, PASS)
    vb = Vault(tmp_path / "b.vault"); vb.seal({"v": "b"}, PASS)

    ra = json.loads(va._path.read_text())
    rb = json.loads(vb._path.read_text())
    ra["keyslots"] = rb["keyslots"]              # slot ajeno, passphrase valid
    va._path.write_text(json.dumps(ra))

    with pytest.raises(VaultAuthError):
        va.open(PASS)


def test_empty_keyslots_rejected(vault):
    raw = json.loads(vault._path.read_text())
    raw["keyslots"] = []
    vault._path.write_text(json.dumps(raw))
    with pytest.raises(VaultCorruptError):
        vault.open(PASS)
