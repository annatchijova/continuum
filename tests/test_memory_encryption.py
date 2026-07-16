"""
tests/test_memory_encryption.py
================================
MemoryField encryption at rest (KL-001): content, embeddings, and tags are
opaque in the database; recall and consolidation are transparent with the key;
migration is rerunnable and plaintext rows can coexist during migration.
"""
from __future__ import annotations

import secrets

import pytest

from legacy.memory.field import MemoryField, MemoryState
from legacy.memory.consolidator import Consolidator
from legacy.ingestion.doc_types import DocCategory

KEY = secrets.token_bytes(32)


def _seed(mf: MemoryField):
    mf.store("will and last wishes before the notary Juan Perez",
             DocCategory.LEGAL, tags=["urgent", "notary"])
    mf.store("bank statement with available account balance",
             DocCategory.FINANCIAL)


# Encryption-at-rest behavior.

def test_content_not_plaintext_on_disk(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    raw = (tmp_path / "m.db").read_bytes()
    for secret in (b"will", b"notary", b"urgent", b"bank", b"Juan"):
        assert secret not in raw, secret


def test_recall_transparent_with_key(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    res = mf.recall("will notary")
    assert res and "will" in res[0].content
    assert res[0].tags == ["urgent", "notary"]


def test_without_key_reveals_nothing(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    blind = MemoryField(tmp_path / "m.db")          # without db_key
    assert blind.recall("will") == []
    assert blind.get_content(mf.recall("will")[0].memory_id) is None


def test_wrong_key_reveals_nothing(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    other = MemoryField(tmp_path / "m.db", db_key=secrets.token_bytes(32))
    assert other.recall("will") == []          # AAD/key cannot decrypt


def test_set_db_key_after_construction(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(mf)
    # A reopened field can receive its key after construction.
    reopened = MemoryField(tmp_path / "m.db")
    assert reopened.recall("will") == []
    reopened.set_db_key(KEY)
    assert reopened.recall("will")


# Plaintext migration behavior.

def test_migrate_plaintext_db(tmp_path):
    # Start with a plaintext database.
    plain = MemoryField(tmp_path / "m.db")
    _seed(plain)
    assert plain.encryption_status()["plaintext"] == 2

    # Migrate all rows to encrypted storage.
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    stats = enc.migrate_encryption()
    assert stats == {"migrated": 2, "skipped": 0}
    assert enc.encryption_status()["encrypted"] == 2

    # Plaintext markers must be scrubbed from the database.
    raw = (tmp_path / "m.db").read_bytes()
    assert b"will" not in raw
    assert enc.recall("will notary")


def test_migrate_scrubs_residual_plaintext(tmp_path):
    """After migration, old plaintext must not survive in free pages or the
    database WAL (VACUUM plus checkpoint)."""
    plain = MemoryField(tmp_path / "m.db")
    plain.store("unique secret phrase xyzzy plugh for the will",
                DocCategory.LEGAL)
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    enc.migrate_encryption()
    blob = b"".join(
        p.read_bytes() for p in tmp_path.glob("m.db*")   # .db, -wal, -shm
    )
    assert b"xyzzy" not in blob and b"secret" not in blob
    assert enc.recall("will xyzzy")               # remains functional


def test_migrate_is_rerunnable(tmp_path):
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    _seed(enc)                                       # encrypted from the first write
    assert enc.migrate_encryption() == {"migrated": 0, "skipped": 2}


def test_mixed_db_is_fully_readable(tmp_path):
    """A partially migrated database (some plaintext, some encrypted rows)
    remains fully readable."""
    plain = MemoryField(tmp_path / "m.db")
    plain.store("document in plaintext before migration about the contract", DocCategory.LEGAL)
    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    enc.store("new document already encrypted about the mortgage", DocCategory.REAL_ESTATE)
    st = enc.encryption_status()
    assert st == {"total": 2, "encrypted": 1, "plaintext": 1}
    # Both plaintext and encrypted rows remain searchable.
    assert enc.recall("contract")
    assert enc.recall("mortgage")


def test_migrate_requires_key(tmp_path):
    plain = MemoryField(tmp_path / "m.db")
    _seed(plain)
    with pytest.raises(RuntimeError):
        plain.migrate_encryption()


# Consolidator behavior with encrypted data.

def test_consolidator_dedups_encrypted_content(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    base = "sales contract house signed before notary in March mortgage deed"
    mf.store(base, DocCategory.LEGAL)
    mf.store(base + " hoy", DocCategory.LEGAL)      # 9/10 = 0.9
    report = Consolidator(mf).run()
    assert report.duplicates_merged >= 1
    assert not report.errors


def test_consolidator_without_key_is_safe(tmp_path):
    """Without the key, the consolidator cannot read encrypted content: it
    does not merge rows, corrupt data, or raise an exception."""
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    base = "sales contract house signed before notary in March mortgage deed"
    mf.store(base, DocCategory.LEGAL)
    mf.store(base + " hoy", DocCategory.LEGAL)
    blind = MemoryField(tmp_path / "m.db")          # without a key
    report = Consolidator(blind).run()
    assert report.duplicates_merged == 0
    assert not report.errors
