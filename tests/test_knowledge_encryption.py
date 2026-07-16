"""
tests/test_knowledge_encryption.py
===================================
KL-001b: encrypted at rest of knowledge.db with search in memory.

each test defiende a invariante and is pone rojo if the encrypted is rompe.
Adversarial: opacidad in disco (content and source_path), ilegibilidad without
key, migracion with scrub, dedup, and composition with the agente (the db_key
compartida encrypts ambas bases and sobrevive to the rekey/recovery).
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

from legacy.knowledge.extractor import KnowledgeBase, KnowledgeDomain
from legacy.agent.memory_agent import LegacyAgent

KEY = secrets.token_bytes(32)
TXT = ("protocol of treatment for pacientes with diagnosis of hipertension "
       "arterial: seguimiento clinical and ajuste of dose. Marcador zzyzx plugh.")
SRC = "/home/anna/historia_clinica_confidencial.txt"


def _blob(tmp_path, glob="k.db*") -> bytes:
    return b"".join(p.read_bytes() for p in tmp_path.glob(glob))


# Implementation note.
# Implementation note.
# Implementation note.

def test_content_and_source_path_not_plaintext_on_disk(tmp_path):
    kb = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    kb.extract_and_store(TXT, source_path=SRC)
    blob = _blob(tmp_path)
    for secret in (b"treatment", b"pacientes", b"zzyzx", b"plugh",
                   b"historia_clinica_confidencial"):
        assert secret not in blob, secret


def test_search_transparent_with_key(tmp_path):
    kb = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    kb.extract_and_store(TXT, source_path=SRC)
    res = kb.search("treatment pacientes zzyzx")
    assert res and res[0].domain == KnowledgeDomain.MEDICINE
    assert "treatment" in res[0].content
    assert res[0].source_path == SRC          # source_path decrypted


def test_without_key_reveals_nothing(tmp_path):
    KnowledgeBase(tmp_path / "k.db", db_key=KEY).extract_and_store(TXT)
    blind = KnowledgeBase(tmp_path / "k.db")           # without a key
    assert blind.search("treatment") == []
    assert blind.by_domain(KnowledgeDomain.MEDICINE) == []
    # Implementation note.
    assert blind.stats()["total"] == 1


def test_wrong_key_reveals_nothing(tmp_path):
    KnowledgeBase(tmp_path / "k.db", db_key=KEY).extract_and_store(TXT)
    other = KnowledgeBase(tmp_path / "k.db", db_key=secrets.token_bytes(32))
    assert other.search("treatment") == []


# Implementation note.
# Implementation note.
# Implementation note.

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
    # Implementation note.
    blob = _blob(tmp_path)
    assert b"zzyzx" not in blob and SRC.encode() not in blob
    assert enc.search("treatment zzyzx")              # sigue buscable


def test_migrate_is_rerunnable(tmp_path):
    enc = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    enc.extract_and_store(TXT)
    assert enc.migrate_encryption() == {"migrated": 0, "skipped": 1}


def test_migrate_requires_key(tmp_path):
    plain = KnowledgeBase(tmp_path / "k.db")
    plain.extract_and_store(TXT)
    with pytest.raises(RuntimeError):
        plain.migrate_encryption()


# Implementation note.
# Implementation note.
# Implementation note.

def test_encrypt_database_covers_knowledge(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT, encoding="utf-8")
    a.ingest(src, extract_knowledge=True)               # crea knowledge.db
    stats = a.encrypt_database("pw")
    assert stats["knowledge"]["migrated"] == 1
    # Implementation note.
    blob = _blob(tmp_path / "data", "knowledge.db*")
    assert b"zzyzx" not in blob
    # Implementation note.
    assert a.knowledge.search("treatment zzyzx")


def test_heir_reads_encrypted_knowledge_after_recovery(tmp_path):
    """INVARIANTE of composition: tras recover by custodios, the heir
    can consultar the database of conocimiento encrypted. Mutacion that atrapa:
    _apply_db_key no propaga the key to the KnowledgeBase."""
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
    """Simula a knowledge.db of <0.6.0: crea and puebla the index FTS5
    external-content with the content in plaintext (as did the code old)."""
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
    """R6-001 (trust-boundary gap): a knowledge.db heredada of <0.6.0 tiene
    the index FTS5 with the terms of the content in plaintext, fuera of the boundary
    of encrypted. `encrypt-db` must dropear ese index and clean sus pages.

    Evidencia of teeth (induccion before/after contra HEAD pre-fix): before of the
    fix 'zzyzxterm' sobrevivia in the .db tras encrypt; with the fix, no. without the
    DROP + VACUUM este test is pone rojo (the term of the index sobrevive)."""
    plain = KnowledgeBase(tmp_path / "k.db")
    e = plain.extract_and_store(
        TXT + " marcador zzyzxterm irrepetible", source_path=SRC
    )
    _add_legacy_fts(tmp_path / "k.db", e)
    # Implementation note.
    assert b"zzyzxterm" in _blob(tmp_path)

    enc = KnowledgeBase(tmp_path / "k.db", db_key=KEY)
    enc.migrate_encryption()

    # Implementation note.
    assert b"zzyzxterm" not in _blob(tmp_path)
    with sqlite3.connect(tmp_path / "k.db") as c:
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert not any(t.startswith("knowledge_fts") for t in tables)
    # Implementation note.
    assert enc.search("treatment zzyzxterm")


def test_r6_001_via_agent_encrypt_database(tmp_path):
    """the same gap by the camino real of the agente: ingest --knowledge in a
    version old, luego encrypt-db."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "notas.txt"
    src.write_text(TXT + " marcador zzyzxterm irrepetible", encoding="utf-8")
    a.ingest(src, extract_knowledge=True)
    # Implementation note.
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
