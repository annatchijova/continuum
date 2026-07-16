"""
tests/test_rekey.py
====================
rotation of passphrase v2: conversion of artifacts a store key + rewrap
of the keyslot, with recovery of estados parciales (crash simulado).
"""
from __future__ import annotations

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.artifact_store import ArtifactStore
from legacy.vault.locker import VaultAuthError

OLD = "passphrase-old"
NEW = "passphrase-new"


@pytest.fixture
def agent(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(OLD)
    for i, text in enumerate([
        "testamento and last voluntad ante the notario",
        "extracto bancario with saldo and movimientos of the cuenta",
    ]):
        src = tmp_path / f"doc{i}.txt"
        src.write_text(text, encoding="utf-8")
        a.ingest(src)
        a.archive_artifact(src, OLD)
    return a


# Implementation note.
# Implementation note.
# Implementation note.

def test_rekey_rotates_vault_and_artifacts_stay_restorable(agent, tmp_path):
    agent.rekey(OLD, NEW)
    agent.lock(NEW)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    # Implementation note.
    with pytest.raises(VaultAuthError):
        fresh.open_owner(OLD)
    # Implementation note.
    fresh.open_owner(NEW)
    for h in fresh._store.list_hashes():
        assert fresh.verify_artifact(h)
        dest = tmp_path / f"out_{h[:8]}.txt"
        fresh.restore_artifact(h, dest, actor="anna")
        assert dest.read_bytes()


def test_rekey_payload_not_reencrypted_only_slot(agent, tmp_path):
    """v2: the rewrap no toca the ciphertext of the payload."""
    import json
    agent.lock(OLD)
    vault_file = tmp_path / "data" / "legacy.vault"
    before = json.loads(vault_file.read_text())["ciphertext"]

    fresh = LegacyAgent(tmp_path / "data", "anna")
    fresh.rekey(OLD, NEW)
    after = json.loads(vault_file.read_text())["ciphertext"]
    assert before == after


def test_rekey_with_wrong_old_passphrase_changes_nothing(agent, tmp_path):
    agent.lock(OLD)
    fresh = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        fresh.rekey("incorrect", NEW)
    fresh.open_owner(OLD)
    assert all(fresh.verify_artifact(h) for h in fresh._store.list_hashes())


def test_rekey_audits_without_leaking_secrets(agent):
    agent.rekey(OLD, NEW)
    events = agent._audit.events()
    assert "PASSPHRASE_ROTATED" in [e["event_type"] for e in events]
    store_key = agent._index.store_key_hex
    for ev in events:
        blob = f"{ev.get('detail','')}{ev.get('artifact','')}"
        assert OLD not in blob and NEW not in blob
        assert store_key not in blob


def test_heir_key_survives_rekey(agent, tmp_path):
    """the keys of heirs are independientes of the passphrase."""
    agent.add_heir("h1", "Olga")
    secret = agent.register_heir_key("h1")
    agent.lock(OLD)

    a2 = LegacyAgent(tmp_path / "data", "anna")
    a2.rekey(OLD, NEW)
    a2.lock(NEW)

    heir = LegacyAgent(tmp_path / "data", "anna")
    assert heir.open_heir("h1", NEW, heir_key=secret) is True


def test_custody_survives_rekey(agent, tmp_path):
    """the property CENTRAL of V2: the shares of custodios repartidos
    before of the rekey siguen recuperando the vault after."""
    shares = agent.setup_custody(OLD, shares=5, threshold=3)
    agent.lock(OLD)

    a2 = LegacyAgent(tmp_path / "data", "anna")
    a2.rekey(OLD, NEW)
    a2.lock(NEW)

    rec = LegacyAgent(tmp_path / "data", "anna")
    rec.recover_with_shares(shares[:3], actor="heir")
    assert rec._index.owner_id == "anna"


def test_rekey_rejects_empty_new_passphrase(agent):
    with pytest.raises(ValueError):
        agent.rekey(OLD, "")


# Implementation note.
# Implementation note.
# Implementation note.

def test_rerun_after_crash_before_rewrap(agent, tmp_path):
    """Crash after of convertir artifacts pero before of the rewrap:
    vault=old (with store key), artifacts=v2. Re-correr complete.
    is adds a artifact v1 heredado (pre-0.3) for that the conversion
    tenga trabajo real."""
    h_legacy = agent._store.put_bytes(b"document heredado v1", OLD)
    assert agent._store.envelope_version(h_legacy) == "1"

    # Implementation note.
    key = agent._ensure_store_key(OLD)
    agent._store.convert_to_key(OLD, key)
    agent.lock(OLD)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    stats = fresh.rekey(OLD, NEW)        # re-corrida: todo already convertido
    assert stats == {"converted": 0, "skipped": 3}

    final = LegacyAgent(tmp_path / "data", "anna")
    final.open_owner(NEW)
    assert all(final.verify_artifact(h) for h in final._store.list_hashes())


def test_rerun_after_crash_mid_conversion(agent, tmp_path):
    """Crash with the conversion a medias: a v1 convertido a mano, another
    v1 pendiente. the re-corrida convierte it that missing."""
    h1 = agent._store.put_bytes(b"document heredado uno", OLD)
    h2 = agent._store.put_bytes(b"document heredado dos", OLD)

    key = agent._ensure_store_key(OLD)
    data = agent._store.get(h1, OLD)
    agent._store._write_envelope(h1, data, key)          # only h1
    agent.lock(OLD)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    stats = fresh.rekey(OLD, NEW)
    assert stats == {"converted": 1, "skipped": 3}       # h2 convertido
    assert fresh._store.envelope_version(h2) == "2"
    fresh2 = LegacyAgent(tmp_path / "data", "anna")
    fresh2.open_owner(NEW)
    assert all(fresh2.verify_artifact(h) for h in fresh2._store.list_hashes())


def test_store_key_persisted_before_any_conversion(agent, tmp_path):
    """the store key is seals in the vault before of convertir the primer
    artifact  a crash inmediatamente after of _ensure_store_key no
    deja artifacts indescifrables."""
    agent._ensure_store_key(OLD)
    # Implementation note.
    fresh = LegacyAgent(tmp_path / "data", "anna")
    fresh.open_owner(OLD)
    assert fresh._index.store_key_hex, "store key no persistida"


def test_store_convert_aborts_on_corrupt_artifact(tmp_path):
    """a artifact that no decrypts aborta the conversion (fail closed)."""
    import secrets as _s
    store = ArtifactStore(tmp_path / "artifacts")
    h = store.put_bytes(b"content", OLD)
    p = store._path_for(h)
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 0xFF
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultAuthError):
        store.convert_to_key(OLD, _s.token_bytes(32))
