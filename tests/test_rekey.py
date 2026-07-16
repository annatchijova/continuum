"""
tests/test_rekey.py
====================
V2 passphrase rotation: artifact conversion to a store key plus keyslot
rewrap, including recovery from partial states (simulated crashes).
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
        "will and last wishes before the notary",
        "extracto bancario with saldo and movimientos of the cuenta",
    ]):
        src = tmp_path / f"doc{i}.txt"
        src.write_text(text, encoding="utf-8")
        a.ingest(src)
        a.archive_artifact(src, OLD)
    return a


# Basic rekey behavior.

def test_rekey_rotates_vault_and_artifacts_stay_restorable(agent, tmp_path):
    agent.rekey(OLD, NEW)
    agent.lock(NEW)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    # The vault remains readable after rotation.
    with pytest.raises(VaultAuthError):
        fresh.open_owner(OLD)
    # Archived artifacts remain restorable.
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
    """Central v2 property: shares distributed before rekey still recover
    the vault afterward."""
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


# Crash-recovery cases.

def test_rerun_after_crash_before_rewrap(agent, tmp_path):
    """Crash after converting artifacts but before rewrap: the vault uses the
    old passphrase and artifacts are v2. Rerunning completes the work. Add a
    legacy v1 artifact (pre-0.3) so conversion has real work."""
    h_legacy = agent._store.put_bytes(b"legacy v1 document", OLD)
    assert agent._store.envelope_version(h_legacy) == "1"

    # Convert the legacy artifact before the simulated crash.
    key = agent._ensure_store_key(OLD)
    agent._store.convert_to_key(OLD, key)
    agent.lock(OLD)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    stats = fresh.rekey(OLD, NEW)        # rerun: everything already converted
    assert stats == {"converted": 0, "skipped": 3}

    final = LegacyAgent(tmp_path / "data", "anna")
    final.open_owner(NEW)
    assert all(final.verify_artifact(h) for h in final._store.list_hashes())


def test_rerun_after_crash_mid_conversion(agent, tmp_path):
    """Crash during conversion: one v1 artifact was converted manually and
    another remains pending. Rerunning converts the missing artifact."""
    h1 = agent._store.put_bytes(b"legacy document one", OLD)
    h2 = agent._store.put_bytes(b"legacy document two", OLD)

    key = agent._ensure_store_key(OLD)
    data = agent._store.get(h1, OLD)
    agent._store._write_envelope(h1, data, key)          # only h1
    agent.lock(OLD)

    fresh = LegacyAgent(tmp_path / "data", "anna")
    stats = fresh.rekey(OLD, NEW)
    assert stats == {"converted": 1, "skipped": 3}       # h2 converted
    assert fresh._store.envelope_version(h2) == "2"
    fresh2 = LegacyAgent(tmp_path / "data", "anna")
    fresh2.open_owner(NEW)
    assert all(fresh2.verify_artifact(h) for h in fresh2._store.list_hashes())


def test_store_key_persisted_before_any_conversion(agent, tmp_path):
    """The store key is sealed before converting the first artifact; a crash
    immediately after _ensure_store_key leaves no artifact unreadable."""
    agent._ensure_store_key(OLD)
    # Simulate a crash immediately after persisting the store key.
    fresh = LegacyAgent(tmp_path / "data", "anna")
    fresh.open_owner(OLD)
    assert fresh._index.store_key_hex, "store key was not persisted"


def test_store_convert_aborts_on_corrupt_artifact(tmp_path):
    """An artifact that cannot decrypt aborts conversion (fail closed)."""
    import secrets as _s
    store = ArtifactStore(tmp_path / "artifacts")
    h = store.put_bytes(b"content", OLD)
    p = store._path_for(h)
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 0xFF
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultAuthError):
        store.convert_to_key(OLD, _s.token_bytes(32))
