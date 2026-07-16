"""
tests/test_encryption_composition.py
======================================
Invariantes of composition between the encrypted at rest (memory.db) and the
demas capas  custodia, recovery by heirs, crash-atomicidad.

Estos invariantes is verificaron by induccion a mano; aca is fijan as
regresion permanente. each test defiende a property load-bearing and is
pone rojo if the cableado is rompe (p. ej. if _apply_db_key deja of llamarse
tras a recovery, the heir recibiria a legado unreadable).
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

from legacy.agent.memory_agent import LegacyAgent

CONTENT = "testamento herencia albacea notario Juan Perez zzyzx"


def _agent_encrypted(tmp_path, passphrase="pw"):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(passphrase)
    src = tmp_path / "t.txt"
    src.write_text(CONTENT, encoding="utf-8")
    a.ingest(src)
    a.encrypt_database(passphrase)
    return a


# Implementation note.
# Implementation note.
# Implementation note.

def test_heir_reads_encrypted_memory_after_custodian_recovery(tmp_path):
    """INVARIANTE: tras recover by custodios and fijar passphrase new, the
    heir can consultar the memory encrypted. Mutacion that atrapa: quitar
    _apply_db_key() of set_passphrase_from_recovery  recall empty."""
    a = _agent_encrypted(tmp_path)
    shares = a.setup_custody("pw", shares=3, threshold=2)
    a.lock("pw")

    heir = LegacyAgent(tmp_path / "data", "anna")
    heir.set_passphrase_from_recovery(shares[:2], "heir-pass", actor="olga")
    res = heir.query("testamento herencia", actor="olga")
    assert len(res) >= 1
    assert "testamento" in res[0].content


def test_heir_reads_encrypted_memory_via_policy(tmp_path):
    """INVARIANTE: a heir admitido by politica (open_heir) reads the
    memory encrypted. Mutacion: quitar _apply_db_key() of the bloque `if granted`."""
    a = _agent_encrypted(tmp_path)
    a.add_heir("h1", "Olga")
    key = a.register_heir_key("h1")
    a.lock("pw")

    heir = LegacyAgent(tmp_path / "data", "anna")
    assert heir.open_heir("h1", "pw", heir_key=key) is True
    res = heir.query("testamento", actor="h1")
    assert len(res) >= 1


def test_owner_reopen_reads_encrypted_memory(tmp_path):
    """INVARIANTE database: the owner that reabre reads su memory encrypted."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert len(b.query("testamento herencia", actor="anna")) >= 1


# Implementation note.
# Implementation note.
# Implementation note.

def test_db_key_survives_rekey(tmp_path):
    """INVARIANTE: rotar the passphrase no rompe the encrypted of memory.db
    (the db_key vive in the payload of the vault, that the rewrap preserves)."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.rekey("pw", "new")
    b.lock("new")
    c = LegacyAgent(tmp_path / "data", "anna")
    c.open_owner("new")
    assert len(c.query("testamento", actor="anna")) >= 1


# Implementation note.
# Implementation note.
# Implementation note.

def test_encrypt_database_is_idempotent(tmp_path):
    """INVARIANTE: correr encrypt-db dos veces no re-encrypts (migrated=0)."""
    a = _agent_encrypted(tmp_path)
    a.lock("pw")
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert b.encrypt_database("pw")["memory"] == {"migrated": 0, "skipped": 1}


# Implementation note.
# Implementation note.
# Implementation note.

def test_crash_between_dbkey_seal_and_migrate_is_recoverable(tmp_path):
    """INVARIANTE: if the proceso muere tras seal the db_key pero before of
    migrar, the state intermedio is LEGIBLE (rows still in plaintext) and re-correr
    encrypt_database it complete. Mutacion that atrapa: seal the db_key
    after of migrar (orden invertido) dejaria rows encrypted with a key
    no persistida  ilegibles tras the crash."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "t.txt"
    src.write_text(CONTENT, encoding="utf-8")
    a.ingest(src)

    # Implementation note.
    a._index.db_key_hex = secrets.token_bytes(32).hex()
    a._vault.seal(a._index.to_dict(), "pw")
    # Implementation note.

    # Implementation note.
    b = LegacyAgent(tmp_path / "data", "anna")
    b.open_owner("pw")
    assert b._index.db_key_hex                       # db_key persistida
    assert b._memory.encryption_status()["plaintext"] == 1   # still in plaintext
    assert len(b.query("testamento", actor="anna")) >= 1     # legible

    # Implementation note.
    assert b.encrypt_database("pw")["memory"]["migrated"] == 1
    assert len(b.query("testamento", actor="anna")) >= 1
    blob = b"".join(p.read_bytes() for p in (tmp_path / "data").glob("memory.db*"))
    assert b"zzyzx" not in blob                       # scrub efectivo
