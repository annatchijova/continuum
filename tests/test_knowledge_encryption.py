"""
tests/test_knowledge_encryption.py
===================================
KL-001b: knowledge.db encryption at rest with in-memory search.

Each test defends an invariant and fails if encryption is broken.
Adversarial coverage includes disk opacity (content and source_path),
unreadability without the key, migration with scrubbing, deduplication, and
agent composition (the shared db_key encrypts both databases and survives
rekey and recovery).
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

from legacy.knowledge.extractor import KnowledgeBase, KnowledgeDomain
from legacy.agent.memory_agent import LegacyAgent

KEY = secrets.token_bytes(32)
TXT = ("Protocol of treatment for patients with arterial hypertension diagnosis: "
       "clinical follow-up and dosage adjustment. Marker zzyzx plugh.")
SRC = "/home/olga/confidential_clinical_history.txt"


def _blob(tmp_path, glob="k.db*") -> bytes:
    return b"".join(p.read_bytes() for p in tmp_path.glob(glob))


# Disk-opacity tests.

def test_content_and_source_path_not_plaintext_on_disk(tmp_path):
    kb = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    kb.extract_and_store(TXT, source_path=SRC)
    blob = _blob(tmp_path)
    for secret in (b"treatment", b"patients", b"zzyzx", b"plugh",
                   b"confidential_clinical_history"):
        assert secret not in blob, secret


def test_search_transparent_with_key(tmp_path):
    kb = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    kb.extract_and_store(TXT, source_path=SRC)
    res = kb.search("treatment patients zzyzx")
    assert res and res[0].domain == KnowledgeDomain.MEDICINE
    assert "treatment" in res[0].content
    assert res[0].source_path == SRC          # source_path decrypted


def test_without_key_reveals_nothing(tmp_path):
    KnowledgeBase(tmp_path / "k.db", db_key=KEY).extract_and_store(TXT)
    blind = KnowledgeBase(tmp_path / "k.db")           # without a key
    assert blind.search("treatment") == []
    assert blind.by_domain(KnowledgeDomain.MEDICINE) == []
    # Row count remains visible while encrypted fields remain opaque.
    assert blind.stats()["total"] == 1


def test_wrong_key_reveals_nothing(tmp_path):
    KnowledgeBase(tmp_path / "k.db", db_key=KEY).extract_and_store(TXT)
    other = KnowledgeBase(tmp_path / "k.db", db_key=secrets.token_bytes(32))
    assert other.search("treatment") == []


# Migration and deduplication tests.

def test_dedup_survives_encryption(tmp_path):
    kb = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    assert kb.extract_and_store(TXT) is not None
    assert kb.extract_and_store(TXT) is None            # content_hash in plaintext

def test_migrate_plaintext_db_scrubs_residual(tmp_path):
    plain = KnowledgeBase(tmp_path / "k.db")
    plain.extract_and_store(TXT, source_path=SRC)
    assert plain.encryption_status()["plaintext"] == 1

    enc = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    assert enc.migrate_encryption() == {"migrated": 1, "skipped": 0}
    assert enc.encryption_status()["encrypted"] == 1
    # A second insert of the same content is deduplicated by content hash.
    blob = _blob(tmp_path)
    assert b"zzyzx" not in blob and SRC.encode() not in blob
    assert enc.search("treatment zzyzx")              # remains searchable


def test_migrate_is_rerunnable(tmp_path):
    enc = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    enc.extract_and_store(TXT)
    assert enc.migrate_encryption() == {"migrated": 0, "skipped": 1}


def test_migrate_requires_key(tmp_path):
    plain = KnowledgeBase(tmp_path / "k.db")
    plain.extract_and_store(TXT)
    with pytest.raises(RuntimeError):
        plain.migrate_encryption()


# Agent composition tests.

def test_encrypt_database_covers_knowledge(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT, encoding="utf-8")
    a.ingest(src, extract_knowledge=True)               # creates knowledge.db
    stats = a.encrypt_database("pw")
    assert stats["knowledge"]["migrated"] == 1
    # The encrypted knowledge database must not expose its marker.
    blob = _blob(tmp_path / "data", "knowledge.db*")
    assert b"zzyzx" not in blob
    # The encrypted knowledge database remains searchable.
    assert a.knowledge.search("treatment zzyzx")


def test_heir_reads_encrypted_knowledge_after_recovery(tmp_path):
    """Composition invariant: after custodian recovery, the heir can query
    the encrypted knowledge database. This catches failures to propagate the
    key to KnowledgeBase in _apply_db_key."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT, encoding="utf-8")
    a.ingest(src, extract_knowledge=True)
    a.encrypt_database("pw")
    shares = a.setup_custody("pw", shares=3, threshold=2)
    a.lock("pw")

    heir = LegacyAgent(tmp_path / "data", "anna")
    heir.set_passphrase_from_recovery(shares[:2], "heir-pass", actor="olga")
    assert heir.knowledge.search("treatment zzyzx")


def _add_legacy_fts(db_path, entry):
    """Simulate a knowledge.db from before 0.6.0 with a legacy FTS5
    external-content index containing plaintext, as the old code did."""
    import json
    conn = sqlite3.connect(db_path)
    conn.executescript(
        'CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5('
        'entry_id UNINDEXED, title, content, keywords_json,'
        'content="knowledge", content_rowid="rowid");'
    )
    conn.execute(
        "INSERT INTO knowledge_fts(entry_id, title, content, keywords_json) "
        "VALUES (?,?,?,?)",
        (entry.entry_id, entry.title, entry.content, json.dumps(entry.keywords)),
    )
    conn.commit()
    conn.close()


def test_r6_001_encrypt_removes_legacy_fts_plaintext(tmp_path):
    """R6-001 (trust-boundary gap): a knowledge.db from before 0.6.0 contains
    an FTS5 index with plaintext content terms outside the encryption boundary.
    `encrypt-db` must drop that index and scrub its pages.

    The marker must not survive encryption after DROP plus VACUUM."""
    plain = KnowledgeBase(tmp_path / "k.db")
    e = plain.extract_and_store(
        TXT + " unique marker zzyzxterm", source_path=SRC
    )
    _add_legacy_fts(tmp_path / "k.db", e)
    # The legacy index initially exposes the marker.
    assert b"zzyzxterm" in _blob(tmp_path)

    enc = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    enc.migrate_encryption()

    # Encryption must remove the legacy index and its plaintext.
    assert b"zzyzxterm" not in _blob(tmp_path)
    with sqlite3.connect(tmp_path / "k.db") as c:
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert not any(t.startswith("knowledge_fts") for t in tables)
    # The legacy index must be removed after encryption.
    assert enc.search("treatment zzyzxterm")


def test_r6_001_via_agent_encrypt_database(tmp_path):
    """The same gap through the agent path: ingest with knowledge enabled in
    a legacy layout, then run encrypt-db."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT + " unique marker zzyzxterm", encoding="utf-8")
    a.ingest(src, extract_knowledge=True)
    # Add a legacy plaintext FTS index.
    entry = a.knowledge.search("treatment")[0]
    _add_legacy_fts(tmp_path / "data" / "knowledge.db", entry)
    assert b"zzyzxterm" in _blob(tmp_path / "data", "knowledge.db*")

    a.encrypt_database("pw")
    assert b"zzyzxterm" not in _blob(tmp_path / "data", "knowledge.db*")


def test_knowledge_db_key_survives_rekey(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT, encoding="utf-8")
    a.ingest(src, extract_knowledge=True)
    a.encrypt_database("pw")
    a.lock("pw")

    b = LegacyAgent(tmp_path / "data", "anna")
    b.rekey("pw", "new")
    b.lock("new")

    c = LegacyAgent(tmp_path / "data", "anna")
    c.open_owner("new")
    assert c.knowledge.search("treatment zzyzx")
