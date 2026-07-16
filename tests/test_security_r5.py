"""
tests/test_security_r5.py
==========================
Ronda R5 of red-team over the encrypted at rest (ver SECURITY_AUDIT_R5.md).

R5-001 (CONFIRMADA by INDUCCION, corregida): in-band signaling. the prefijo
that marca ciphertext (`gcmf1:`) is content in plaintext valid; a document
that empezara with el is volvia invisible (recall it descartaba) and, peor, the
migracion it dejaba in plaintext dentro of a database "encrypted". Corregido
escapando the plaintext in the escritura and quitando the heuristica of
"already parece encrypted" of encrypt_field.

the resto fija as regresion permanente the vectores DESCARTADOS of the
ronda (H1H7): that sigan descartados.
"""
from __future__ import annotations

import secrets
import sqlite3

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.core.dbcrypto import FIELD_PREFIX, PLAIN_ESCAPE
from legacy.memory.field import MemoryField
from legacy.ingestion.doc_types import DocCategory

KEY = secrets.token_bytes(32)
PASS = "pw"


# Implementation note.
# Implementation note.
# Implementation note.

@pytest.mark.parametrize("prefix", [FIELD_PREFIX, PLAIN_ESCAPE])
def test_r5_001_prefix_like_content_plaintext_db(tmp_path, prefix):
    """content that starts with the prefijo magico, in database without encrypt, is
    recupera igual (before is volvia invisible)."""
    mf = MemoryField(tmp_path / "m.db")
    mid = mf.store(prefix + "esto is text real over the testamento and the herencia",
                   DocCategory.LEGAL, tags=["urgente"])
    res = mf.recall("testamento herencia")
    assert any(r.memory_id == mid for r in res)
    r = next(r for r in res if r.memory_id == mid)
    assert r.content.startswith(prefix)          # content exacto preservado
    assert r.tags == ["urgente"]


def test_r5_001_prefix_like_content_survives_migration(tmp_path):
    """and sobrevive the encrypted: is encrypts of verdad (no remains in plaintext) and sigue
    siendo legible with the key."""
    mf = MemoryField(tmp_path / "m.db")
    secret = FIELD_PREFIX + "content colisionante irrepetible zzyzx testamento"
    mid = mf.store(secret, DocCategory.LEGAL)

    enc = MemoryField(tmp_path / "m.db", db_key=KEY)
    assert enc.migrate_encryption()["migrated"] == 1
    # Implementation note.
    res = enc.recall("testamento zzyzx")
    assert res and res[0].content == secret
    # Implementation note.
    blob = b"".join(p.read_bytes() for p in tmp_path.glob("m.db*"))
    assert b"zzyzx" not in blob


def test_r5_001_encrypt_field_no_longer_guesses(tmp_path):
    """the causa raiz: encrypt_field encrypts su entry aunque parezca a token."""
    from legacy.core.dbcrypto import FieldCipher
    c = FieldCipher(KEY)
    plain = FIELD_PREFIX + "no soy a token, soy text"
    tok = c.encrypt_field(plain, "aad")
    assert tok != plain and c.decrypt_field(tok, "aad") == plain


# Implementation note.
# Implementation note.
# Implementation note.

def test_h1_embedding_is_encrypted(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    mf.store("hipoteca banco credito prestamo cuenta saldo", DocCategory.FINANCIAL)
    conn = sqlite3.connect(tmp_path / "m.db")
    row = conn.execute("SELECT embedding_json, tags_json FROM memories").fetchone()
    conn.close()
    assert row[0].startswith(FIELD_PREFIX)       # embedding encrypted
    assert row[1].startswith(FIELD_PREFIX)       # tags encrypted


# Implementation note.
# Implementation note.
# Implementation note.

def test_h2_content_moved_between_rows_rejected(tmp_path):
    mf = MemoryField(tmp_path / "m.db", db_key=KEY)
    mf.store("testamento herencia albacea notario", DocCategory.LEGAL)
    b = mf.store("hipoteca banco credito", DocCategory.FINANCIAL)
    conn = sqlite3.connect(tmp_path / "m.db")
    a_content = conn.execute("SELECT content FROM memories ORDER BY created_at").fetchone()[0]
    conn.execute("UPDATE memories SET content=? WHERE memory_id=?", (a_content, b))
    conn.commit(); conn.close()
    # Implementation note.
    assert all(r.memory_id != b for r in mf.recall("testamento herencia"))


# Implementation note.
# Implementation note.
# Implementation note.

def _agent_with_encrypted_memory(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    src = tmp_path / "t.txt"
    src.write_text("contract compraventa casa ante notario Juan", encoding="utf-8")
    a.ingest(src)
    a.encrypt_database(PASS)
    return a


def test_h3_ghost_detected_with_encrypted_content(tmp_path):
    a = _agent_with_encrypted_memory(tmp_path)
    conn = sqlite3.connect(tmp_path / "data" / "memory.db")
    conn.execute(
        "INSERT INTO memories (memory_id,category,content,content_hash,artifact,"
        "state,score,recall_count,last_access,created_at,embedding_json,tags_json) "
        "VALUES ('ghost','legal','x','deadbeef','','NEUTRAL',1.0,0,0,0,'[]','[]')"
    )
    conn.commit(); conn.close()
    vi = a.verify_memory_integrity()
    assert not vi["ok"] and any("ghost" in e for e in vi["errors"])


def test_h6_tampered_ciphertext_detected(tmp_path):
    a = _agent_with_encrypted_memory(tmp_path)
    conn = sqlite3.connect(tmp_path / "data" / "memory.db")
    mid, tok = conn.execute("SELECT memory_id, content FROM memories").fetchone()
    bad = tok[:-4] + ("AAAA" if tok[-4:] != "AAAA" else "BBBB")
    conn.execute("UPDATE memories SET content=? WHERE memory_id=?", (bad, mid))
    conn.commit(); conn.close()
    vi = a.verify_memory_integrity()
    assert not vi["ok"] and any("unreadable" in e or "altered" in e for e in vi["errors"])


def test_h7_full_row_content_swap_detected(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    for n, txt in [("uno", "testamento herencia albacea"),
                   ("dos", "hipoteca banco credito")]:
        s = tmp_path / f"{n}.txt"; s.write_text(txt, encoding="utf-8"); a.ingest(s)
    a.encrypt_database(PASS)
    conn = sqlite3.connect(tmp_path / "data" / "memory.db"); conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT memory_id, content, content_hash FROM memories ORDER BY created_at")]
    A, B = rows
    conn.execute("UPDATE memories SET content=?, content_hash=? WHERE memory_id=?",
                 (B["content"], B["content_hash"], A["memory_id"]))
    conn.execute("UPDATE memories SET content=?, content_hash=? WHERE memory_id=?",
                 (A["content"], A["content_hash"], B["memory_id"]))
    conn.commit(); conn.close()
    assert not a.verify_memory_integrity()["ok"]      # cross-check of the vault it atrapa


# Implementation note.
# Implementation note.
# Implementation note.

def test_h4_recall_survives_rekey_on_encrypted_db(tmp_path):
    a = _agent_with_encrypted_memory(tmp_path)
    a.lock(PASS)
    b = LegacyAgent(tmp_path / "data", "anna")
    b.rekey(PASS, "new")
    b.lock("new")
    c = LegacyAgent(tmp_path / "data", "anna")
    c.open_owner("new")
    assert len(c.query("contract compraventa", actor="anna")) >= 1
