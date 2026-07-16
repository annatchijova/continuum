"""
tests/test_security_r3.py
==========================
Regressions for the findings from audit R3.

Covers emergent properties: composition, global invariants, recovery,
concurrency, cumulative degradation, and cryptographic consistency.
"""
import sqlite3
import time
from pathlib import Path

import pytest


def test_r3_001_integrity_passes_on_clean_db(tmp_path):
    """verify_memory_integrity() returns ok=True when memory.db is unchanged."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "will.txt"
    doc.write_text("This is my will.")
    agent.ingest(doc)

    result = agent.verify_memory_integrity()
    assert result["ok"] is True
    assert result["checked"] == 1
    assert result["errors"] == []


def test_r3_001_integrity_detects_content_tamper(tmp_path):
    """
    verify_memory_integrity() detects content modified directly in memory.db
    with a SQLite editor.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "contract.txt"
    doc.write_text("Purchase contract signed on 2025-01-01.")
    record = agent.ingest(doc)

    db_path = tmp_path / "data" / "memory.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE memories SET content=? WHERE memory_id=?",
            ("content forged by the attacker", record.memory_id),
        )

    result = agent.verify_memory_integrity()
    assert result["ok"] is False
    assert result["checked"] == 1
    assert any("altered" in e for e in result["errors"])


def test_r3_001_integrity_detects_missing_memory(tmp_path):
    """
    verify_memory_integrity() detects when a memory.db row is deleted.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "life_insurance.txt"
    doc.write_text("Life insurance policy number 12345.")
    record = agent.ingest(doc)

    db_path = tmp_path / "data" / "memory.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM memories WHERE memory_id=?", (record.memory_id,))

    result = agent.verify_memory_integrity()
    assert result["ok"] is False
    assert any("missing" in e for e in result["errors"])


def test_r3_001_integrity_logs_audit_event(tmp_path):
    """verify_memory_integrity() always records an INTEGRITY_CHECK event."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")
    agent.verify_memory_integrity()

    events = agent._audit.events(event_type="INTEGRITY_CHECK")
    assert len(events) == 1
    assert "memory_integrity" in events[0]["detail"]


def test_r3_001_integrity_multiple_artifacts(tmp_path):
    """With N artifacts, verify_memory_integrity() checks all of them."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    for i in range(5):
        doc = tmp_path / f"doc_{i}.txt"
        doc.write_text(f"Document {i}: legacy content.")
        agent.ingest(doc)

    result = agent.verify_memory_integrity()
    assert result["ok"] is True
    assert result["checked"] == 5


def test_r3_002_vocab_capped_during_session(tmp_path):
    """
    After ingesting many documents with diverse vocabulary,
    _vocab does not exceed _MAX_VOCAB_SIZE.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    for i in range(200):
        mf.store(
            f"unique_word{i} specific_term{i} novel_concept{i} new_definition{i}",
            DocCategory.PERSONAL,
        )

    assert len(mf._vocab) <= mf._MAX_VOCAB_SIZE


def test_r3_002_embedding_length_bounded(tmp_path):
    """The embedding stored in the database never exceeds _MAX_VOCAB_SIZE floats."""
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory
    import json

    mf = MemoryField(tmp_path / "mem.db")
    for i in range(100):
        mf.store(f"term{i} word{i} concept{i}", DocCategory.PROFESSIONAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        rows = conn.execute("SELECT embedding_json FROM memories").fetchall()

    for row in rows:
        emb = json.loads(row[0] or "[]")
        assert len(emb) <= mf._MAX_VOCAB_SIZE


def test_r3_003_score_does_not_overflow(tmp_path):
    """After many reinforce() calls, score does not reach float('inf')."""
    import math
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("important legal document", DocCategory.LEGAL)

    for _ in range(600):
        mf.reinforce(mid)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        score = conn.execute(
            "SELECT score FROM memories WHERE memory_id=?", (mid,)
        ).fetchone()[0]

    assert not math.isinf(score), "score reached float('inf')"
    assert not math.isnan(score), "score reached NaN"
    assert score <= mf._MAX_SCORE + 1e-6


def test_r3_003_score_cap_value():
    """_MAX_SCORE is defined as a positive finite float."""
    from legacy.memory.field import MemoryField
    import math
    assert hasattr(MemoryField, "_MAX_SCORE")
    assert math.isfinite(MemoryField._MAX_SCORE)
    assert MemoryField._MAX_SCORE > 0


def test_c001_low_confidence_wrong_category_missed_by_filtered_recall(tmp_path):
    """
    A document classified into the wrong category (LOW confidence) does not
    appear in recall(category=correct_category). This is expected behavior,
    documented as C-001.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("mortgage deed property real estate bank", DocCategory.LEGAL)

    results = mf.recall("mortgage property", category=DocCategory.REAL_ESTATE)
    assert not any(r.memory_id == mid for r in results),\
        "the document in the wrong category should not appear in filtered recall"

    results_all = mf.recall("mortgage property")
    assert any(r.memory_id == mid for r in results_all)


def test_global_inv_no_double_vault_created(tmp_path):
    """
    initialize() fails when the vault already exists; a vault cannot have
    two VAULT_CREATED events.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    with pytest.raises(ValueError, match="The vault already exists"):
        agent.initialize("pass")

    events = agent._audit.events(event_type="VAULT_CREATED")
    assert len(events) == 1


def test_global_inv_synaptic_weights_never_exceed_max(tmp_path):
    """STDP_MAX_WEIGHT is the strict ceiling for all synaptic weights."""
    from legacy.memory.field import MemoryField, STDP_MAX_WEIGHT
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    for i in range(30):
        mf.store(f"legal contract inheritance {i}", DocCategory.LEGAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        max_w = conn.execute("SELECT MAX(weight) FROM synaptic_links").fetchone()[0]
    if max_w is not None:
        assert max_w <= STDP_MAX_WEIGHT + 1e-9


def test_degradation_recall_stable_after_many_stores(tmp_path):
    """
    Recall continues returning relevant results after ingesting many documents
    from different categories.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    target_mid = mf.store(
        "will last wishes assets inheritance legacy",
        DocCategory.LEGAL,
    )

    for i in range(200):
        cat = [DocCategory.MEDICAL, DocCategory.FINANCIAL, DocCategory.PERSONAL][i % 3]
        mf.store(f"document {i} generic content unrelated to the will", cat)

    results = mf.recall("will inheritance legacy")
    assert any(r.memory_id == target_mid for r in results[:5]),\
        "the will memory was displaced by noise after 200 stores"


def test_degradation_forget_then_recall_excludes_forgotten(tmp_path):
    """
    A memory marked FORGOTTEN never appears in recall(), even with a high
    historical score.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("mortgage bank deed property", DocCategory.REAL_ESTATE)
    mf.reinforce(mid)  # Raise the score.
    mf.forget(mid)

    results = mf.recall("mortgage bank property")
    assert not any(r.memory_id == mid for r in results),\
        "FORGOTTEN memory appeared in recall()"


def test_recovery_vault_tmp_cleaned_on_success(tmp_path):
    """After a successful seal(), no .tmp file remains."""
    from legacy.vault.locker import Vault

    v = Vault(tmp_path / "x.vault")
    v.seal({"k": "v"}, "pass")
    assert not (tmp_path / "x.tmp").exists()


def test_recovery_vault_original_survives_if_tmp_fails(tmp_path, monkeypatch):
    """
    If writing the .tmp file fails, the original vault is not corrupted.
    Atomic writing (tmp -> rename) guarantees that the original remains
    intact until writing to .tmp completes.
    """
    from legacy.vault.locker import Vault

    v = Vault(tmp_path / "x.vault")
    v.seal({"original": True}, "pass")

    assert v.open("pass")["original"] is True

    def always_fail(self, data, *args, **kwargs):
        raise OSError("Simulated disk full")

    monkeypatch.setattr(Path, "write_text", always_fail)

    with pytest.raises(OSError, match="Simulated disk full"):
        v.seal({"tampered": True}, "pass")

    monkeypatch.undo()

    recovered = v.open("pass")
    assert recovered["original"] is True
    assert "tampered" not in recovered


def test_crypto_consistency_vault_hash_chain_still_valid_after_r3_changes(tmp_path):
    """
    After all R3 corrections, verify_audit() still returns a valid chain.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "doc.txt"
    doc.write_text("sample content for the audit chain.")
    agent.ingest(doc)

    mid = agent._memory.stats()
    agent.reinforce_memory(
        list(agent._memory.recall("sample content"))[0].memory_id
    )
    agent.verify_memory_integrity()

    audit_result = agent.verify_audit(hmac_key=b"key123456789012!")
    assert audit_result["valid"] is True
    assert audit_result["broken_links"] == []
    assert audit_result["tampered_content"] == []
    assert audit_result["seq_discontinuities"] == []
    assert audit_result["hmac_failures"] == []
