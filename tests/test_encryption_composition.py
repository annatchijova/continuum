"""
tests/test_encryption_composition.py
======================================
Composition invariants between encryption at rest (memory.db) and the other
layers: custody, heir recovery, and crash atomicity.

These invariants were previously checked manually; here they become permanent
regressions. Each test defends a load-bearing property and fails if the wiring
breaks, for example if _apply_db_key is not called after recovery.
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

from legacy.agent.memory_agent import LegacyAgent

CONTENT = "will inheritance executor notary Juan Perez zzyzx"


def _agent_encrypted(tmp_path, passphrase="pw"):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(passphrase)
    src = tmp_path / "t.txt"
    src.write_text(CONTENT, encoding="utf-8")
    a.ingest(src)
    a.encrypt_database(passphrase)
    return a


# Custodian-recovery composition.

def test_heir_reads_encrypted_memory_after_custodian_recovery(tmp_path):
    """Invariant: after custodian recovery and setting a new passphrase, the
    heir can query encrypted memory. This catches removing _apply_db_key() from
    set_passphrase_from_recovery, which would produce empty recall results."""
    a = _agent_encrypted(tmp_path)
    shares = a.setup_custody("pw", shares=3, threshold=2)
    a.lock("pw")

    heir = LegacyAgent(tmp_path / "data", "anna")
    heir.set_passphrase_from_recovery(shares[:2], "heir-pass", actor="olga")
    res = heir.query("will inheritance", actor="olga")
    assert len(res) >= 1
    assert "will" in res[0].content


def test_heir_reads_encrypted_memory_via_policy(tmp_path):
    """Invariant: an heir admitted by policy (open_heir) reads encrypted
    memory. This catches removing _apply_db_key() from the granted branch."""
    a = _agent_encrypted(tmp_path)
    a.add_heir("h1", "Olga")
    key = a.register_heir_key("h1")
    a.lock("pw")

    heir = LegacyAgent(tmp_path / "data", "anna")
    assert heir.open_heir("h1", "pw", heir_key=key) is True
    res = heir.query("will", actor="h1")
    assert len(res) >= 1


def test_owner_reopen_reads_encrypted_memory(tmp_path):
    """Database invariant: a reopened owner reads encrypted memory."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert len(b.query("will inheritance", actor="anna")) >= 1


# Rekey composition.

def test_db_key_survives_rekey(tmp_path):
    """Invariant: rotating the passphrase does not break memory.db encryption
    because the vault payload preserves the db_key during rewrap."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.rekey("pw", "new")
    b.lock("new")
    c = LegacyAgent(tmp_path / "data", "anna")
    c.open_owner("new")
    assert len(c.query("will", actor="anna")) >= 1


# Idempotence.

def test_encrypt_database_is_idempotent(tmp_path):
    """Invariant: running encrypt-db twice does not re-encrypt rows."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert b.encrypt_database("pw")["memory"] == {"migrated": 0, "skipped": 1}


# Crash-safe key persistence.

def test_crash_between_dbkey_seal_and_migrate_is_recoverable(tmp_path):
    """Invariant: if the process stops after sealing db_key but before
    migration, the intermediate state remains readable and rerunning
    encrypt_database completes it. This catches sealing the key after migration,
    which would leave rows encrypted with a non-persisted key."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "t.txt"
    src.write_text(CONTENT, encoding="utf-8")
    a.ingest(src)

    # Persist the key before migrating rows.
    a._index.db_key_hex = secrets.token_bytes(32).hex()
    a._vault.seal(a._index.to_dict(), "pw")
    # Simulate a fresh process after the crash point.

    # The persisted key makes plaintext rows readable.
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert b._index.db_key_hex                       # db_key persisted
    assert b._memory.encryption_status()["plaintext"] == 1   # still plaintext
    assert len(b.query("will", actor="anna")) >= 1     # readable

    # Finish the migration and verify the marker was scrubbed.
    assert b.encrypt_database("pw")["memory"]["migrated"] == 1
    assert len(b.query("will", actor="anna")) >= 1
    blob = b"".join(p.read_bytes() for p in (tmp_path / "data").glob("memory.db*"))
    assert b"zzyzx" not in blob                       # scrub efectivo
