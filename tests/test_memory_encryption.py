"""
tests/test_memory_encryption.py
================================
MemoryField encrypted at rest (KL-001): content/embedding/tags opacos in
the .db, recall/consolidate transparentes with the key, migracion
re-ejecutable, and coexistencia with rows in plaintext.
"""
from __future__ import annotations

import secrets

import pytest

from legacy.memory.field import MemoryField, MemoryState
from legacy.memory.consolidator import Consolidator
from legacy.ingestion.doc_types import DocCategory

KEY = secrets.token_bytes(32)


def _seed(mf: MemoryField):
    mf.store("testamento and last voluntad ante the notario Juan Perez",
             DocCategory.LEGAL, tags=["urgente", "notaria"])
    mf.store("extracto bancario with saldo disponible of the cuenta",
             DocCategory.FINANCIAL)


# Implementation note.
# Implementation note.
# Implementation note.

def test_content_not_plaintext_on_disk(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    raw = (tmp_path / "m.db").read_bytes()
    for secret in (b"testamento", b"notario", b"urgente", b"bancario", b"Juan"):
        assert secret not in raw, secret


def test_recall_transparent_with_key(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    res = mf.recall("testamento notario")
    assert res and "testamento" in res[0].content
    assert res[0].tags == ["urgente", "notaria"]


def test_without_key_reveals_nothing(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    blind = MemoryField(tmp_path / "m.db")          # without db_key
    assert blind.recall("testamento") == []
    assert blind.get_content(mf.recall("testamento")[0].memory_id) is None


def test_wrong_key_reveals_nothing(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    other = MemoryField(tmp_path / "m.db", db_key=secrets.token_bytes(32))
    assert other.recall("testamento") == []          # AAD/key no descifran


def test_set_db_key_after_construction(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    # Implementation note.
    reopened = MemoryField(tmp_path / "m.db")
    assert reopened.recall("testamento") == []
    reopened.set_db_key(KEY)
    assert reopened.recall("testamento")


# Implementation note.
# Implementation note.
# Implementation note.

def test_migrate_plaintext_db(tmp_path):
    # Implementation note.
    plain = MemoryField(tmp_path / "m.db")
    _seed(plain)
    assert plain.encryption_status()["plaintext"] == 2

    # Implementation note.
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    stats = enc.migrate_encryption()
    assert stats == {"migrated": 2, "skipped": 0}
    assert enc.encryption_status()["encrypted"] == 2

    # Implementation note.
    raw = (tmp_path / "m.db").read_bytes()
    assert b"testamento" not in raw
    assert enc.recall("testamento notario")


def test_migrate_scrubs_residual_plaintext(tmp_path):
    """Tras migrar, the plaintext old NO must sobrevivir in pages libres
    ni in the WAL of the file (VACUUM + checkpoint)."""
    plain = MemoryField(tmp_path / "m.db")
    plain.store("frase secreta irrepetible xyzzy plugh for the testamento",
                DocCategory.LEGAL)
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    enc.migrate_encryption()
    blob = b"".join(
        p.read_bytes() for p in tmp_path.glob("m.db*")   # .db, -wal, -shm
    )
    assert b"xyzzy" not in blob and b"secreta" not in blob
    assert enc.recall("testamento xyzzy")               # sigue funcionando


def test_migrate_is_rerunnable(tmp_path):
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(enc)                                       # already encrypted to the write
    assert enc.migrate_encryption() == {"migrated": 0, "skipped": 2}


def test_mixed_db_is_fully_readable(tmp_path):
    """a database a medio migrar (algunas rows in plaintext, otras encrypted)
    is reads complete."""
    plain = MemoryField(tmp_path / "m.db")
    plain.store("document in plaintext pre-migracion over the contract", DocCategory.LEGAL)
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    enc.store("document new already encrypted over the hipoteca", DocCategory.REAL_ESTATE)
    st = enc.encryption_status()
    assert st == {"total": 2, "encrypted": 1, "plaintext": 1}
    # Implementation note.
    assert enc.recall("contract")
    assert enc.recall("hipoteca")


def test_migrate_requires_key(tmp_path):
    plain = MemoryField(tmp_path / "m.db")
    _seed(plain)
    with pytest.raises(RuntimeError):
        plain.migrate_encryption()


# Implementation note.
# Implementation note.
# Implementation note.

def test_consolidator_dedups_encrypted_content(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    # Implementation note.
    base = "contract compraventa casa firmado ante notario marzo hipoteca escritura"
    mf.store(base, DocCategory.LEGAL)
    mf.store(base + " hoy", DocCategory.LEGAL)      # 9/10 = 0.9
    report = Consolidator(mf).run()
    assert report.duplicates_merged >= 1
    assert not report.errors


def test_consolidator_without_key_is_safe(tmp_path):
    """without the key, the consolidator no can leer content encrypted: no
    fusiona (no participa) pero tampoco corrompe ni lanza."""
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    base = "contract compraventa casa firmado ante notario marzo hipoteca escritura"
    mf.store(base, DocCategory.LEGAL)
    mf.store(base + " hoy", DocCategory.LEGAL)
    blind = MemoryField(tmp_path / "m.db")          # without a key
    report = Consolidator(blind).run()
    assert report.duplicates_merged == 0
    assert not report.errors
