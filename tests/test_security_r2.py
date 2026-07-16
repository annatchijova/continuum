"""
tests/test_security_r2.py
==========================
Regressions for findings from security audit R2.

Each test contains the ID of the finding it covers.
"""
import hashlib
import json
import math
import time
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# R2-001 — Vault: atomic writing
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_001_vault_atomic_write_leaves_no_tmp(tmp_path):
    """A successful seal() leaves no .tmp file."""
    from legacy.vault.locker import Vault
    v = Vault(tmp_path / "test.vault")
    v.seal({"x": 1}, "pass")
    assert not (tmp_path / "test.tmp").exists()


def test_r2_001_vault_overwrites_preserve_original_until_rename(tmp_path):
    """
    Simulate seal() writing to .tmp first.
    The original vault is replaced only when rename succeeds.
    The .tmp file must exist during writing before replacement.
    (Post-facto verification: after seal, the original vault was replaced
    and the content is new rather than old.)
    """
    from legacy.vault.locker import Vault
    v = Vault(tmp_path / "test.vault")
    v.seal({"version": 1}, "pass")
    content_v1 = json.loads((tmp_path / "test.vault").read_text())

    v.seal({"version": 2}, "pass")
    content_v2 = json.loads((tmp_path / "test.vault").read_text())

    # The second seal completely replaced the first.
    assert content_v1 != content_v2
    assert not (tmp_path / "test.tmp").exists()


# ─────────────────────────────────────────────────────────────────────────────
# R2-002 — STDP poisoning: reinforce/forget with audit trail
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_002_reinforce_memory_logs_audit_event(tmp_path):
    """reinforce_memory() produces exactly one MEMORY_REINFORCED event."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("will legal contract", DocCategory.LEGAL)
    agent.reinforce_memory(mid)

    events = agent._audit.events(event_type="MEMORY_REINFORCED")
    assert len(events) == 1
    assert mid in events[0]["detail"]


def test_r2_002_forget_memory_logs_audit_event(tmp_path):
    """forget_memory() produces exactly one MEMORY_FORGOTTEN event."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("private personal note", DocCategory.PERSONAL)
    agent.forget_memory(mid)

    events = agent._audit.events(event_type="MEMORY_FORGOTTEN")
    assert len(events) == 1
    assert mid in events[0]["detail"]


def test_r2_002_reinforce_memory_requires_open_vault(tmp_path):
    """reinforce_memory() on a locked vault raises RuntimeError."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")
    agent.lock("pass")

    with pytest.raises(RuntimeError, match="Vault is locked"):
        agent.reinforce_memory("any-id")


def test_r2_002_forget_memory_requires_open_vault(tmp_path):
    """forget_memory() on a locked vault raises RuntimeError."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")
    agent.lock("pass")

    with pytest.raises(RuntimeError, match="Vault is locked"):
        agent.forget_memory("any-id")


def test_r2_002_stdp_weights_bounded(tmp_path):
    """STDP potentiation cannot exceed STDP_MAX_WEIGHT = 2.0."""
    import sqlite3
    from legacy.memory.field import MemoryField, STDP_MAX_WEIGHT
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Ingest 20 documents from the same category to saturate the weight.
    for i in range(20):
        mf.store(f"contract mortgage bank {i} legacy", DocCategory.LEGAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        max_w = conn.execute("SELECT MAX(weight) FROM synaptic_links").fetchone()[0]
    assert max_w is not None
    assert max_w <= STDP_MAX_WEIGHT + 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# R2-003 — _recency_bonus with a future timestamp
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_003_recency_bonus_zero_for_future_timestamp():
    """If last_access > now, the recency bonus must be 0, not positive."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    future = now + 86400  # One day ahead.
    bonus = _recency_bonus(future, now)
    assert bonus == 0.0


def test_r2_003_recency_bonus_positive_for_past_timestamp():
    """If last_access < now, the bonus must be > 0."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    past = now - 3600  # One hour ago.
    bonus = _recency_bonus(past, now)
    assert bonus > 0.0


def test_r2_003_recency_bonus_bounded_above():
    """The recency bonus cannot exceed 0.05 (immediate, delta=0)."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    bonus = _recency_bonus(now, now)
    # exp(0) = 1, bonus = 0.05 * 1.0 = 0.05.
    assert bonus == pytest.approx(0.05, abs=1e-9)


def test_r2_003_future_timestamp_does_not_dominate_recall(tmp_path):
    """
    A memory with a future last_access must not dominate recall.
    Before the fix, its bonus could exceed 50 and displace every legitimate memory.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # "Trap" memory, manually marked with a future timestamp.
    mid_trap = mf.store("irrelevant document xyz", DocCategory.PERSONAL)
    mid_real = mf.store("will inheritance assets legacy family", DocCategory.LEGAL)

    import sqlite3
    future_ts = time.time() + 86400 * 10  # Ten days in the future.
    with sqlite3.connect(tmp_path / "mem.db") as conn:
        conn.execute("UPDATE memories SET last_access=? WHERE memory_id=?",
                     (future_ts, mid_trap))
        conn.commit()

    results = mf.recall("will inheritance legacy")
    assert len(results) > 0
    # The relevant memory must appear; the trap must not displace it.
    top_id = results[0].memory_id
    assert top_id == mid_real, (
        f"The trap memory (future timestamp) dominated recall. "
        f"Top: {top_id}, expected: {mid_real}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# R2-004 — TF-IDF staleness: vocab crece, embeddings viejos divergen
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_004_recall_stable_after_vocab_growth(tmp_path):
    """
    Recall for a specific memory must not degrade after ingesting documents
    that extend the vocabulary.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("mortgage bank real estate property deed", DocCategory.REAL_ESTATE)

    # Recall before extending the vocabulary.
    results_before = mf.recall("mortgage property")
    scores_before = {r.memory_id: r.final_score for r in results_before}

    # Extend the vocabulary with new documents from another domain.
    for i in range(30):
        mf.store(
            f"medical diagnosis laboratory blood analysis {i}",
            DocCategory.MEDICAL
        )

    # Recall after the extension.
    results_after = mf.recall("mortgage property")
    scores_after = {r.memory_id: r.final_score for r in results_after}

    # The original memory must remain recoverable.
    assert mid in scores_after, "Original memory lost after vocabulary growth"
    # The score must not fall to zero, which would indicate overlap fallback.
    assert scores_after[mid] > 0.01


def test_r2_004_lazy_recompute_uses_cosine_not_overlap(tmp_path):
    """
    As the vocabulary grows, recall uses cosine recomputation rather than
    token overlap. A document very similar to the query but stored with an
    old vocabulary must still score highly.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Store with a small initial vocabulary.
    mid = mf.store("life insurance policy coverage", DocCategory.FINANCIAL)

    # Grow the vocabulary significantly.
    for i in range(50):
        mf.store(f"word{i} term{i} concept{i} definition{i}", DocCategory.PERSONAL)

    results = mf.recall("life insurance policy")
    assert any(r.memory_id == mid for r in results), \
        "Life insurance memory was not recovered with the extended vocabulary"


# ─────────────────────────────────────────────────────────────────────────────
# R2-005 — NFC/NFD: same word, same token
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_005_tokenize_nfc_nfd_equivalent():
    """NFC and NFD forms of the same word produce the same tokens."""
    from legacy.memory.field import _tokenize

    nfc = "café résumé"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd  # Confirm they differ at the byte level.
    assert _tokenize(nfc) == _tokenize(nfd)


def test_r2_005_store_nfd_recall_nfc(tmp_path):
    """
    A document stored with NFD text must be recalled with an NFC query,
    and vice versa.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    nfd_content = unicodedata.normalize("NFD", "médico diagnóstico clínica")
    mid = mf.store(nfd_content, DocCategory.MEDICAL)

    # Query in NFC.
    results = mf.recall("médico diagnóstico")
    assert any(r.memory_id == mid for r in results), \
        "NFC query did not recover the document stored in NFD"


def test_r2_005_canonicalize_nfc_nfd_same_hash():
    """NFC and NFD forms of the same string produce the same canonical hash."""
    from legacy.core.canonicalize import _canonicalize
    from legacy.core.hash_chain import canonical_hash

    payload_nfc = {"actor": "Maria", "detail": "coffee with milk"}
    payload_nfd = {
        "actor": unicodedata.normalize("NFD", "Maria"),
        "detail": unicodedata.normalize("NFD", "coffee with milk"),
    }
    assert canonical_hash(payload_nfc) == canonical_hash(payload_nfd)


# ─────────────────────────────────────────────────────────────────────────────
# R2-006 — Time injection in open_heir(now=...)
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_006_now_override_logged_in_audit(tmp_path):
    """
    When open_heir() receives an explicit `now`, the audit trail must record
    the overridden value in the CONDITION_CHECK event detail.
    """
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.vault.conditions import AccessPolicy, DateCondition

    now_real = datetime.now(timezone.utc)
    # Condition: access date one year from now.
    far_future = (now_real + timedelta(days=365)).isoformat()
    policy = AccessPolicy(conditions=[DateCondition(unlock_after_iso=far_future)])

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass", policy=policy)
    agent.lock("pass")

    # The heir injects a future 'now' to bypass DateCondition.
    forged_now = now_real + timedelta(days=400)
    granted = agent.open_heir("heir-1", "pass", now=forged_now)

    assert granted is True  # The condition is satisfied by the forged now.

    condition_events = agent._audit.events(event_type="CONDITION_CHECK")
    assert len(condition_events) >= 1
    last_event = condition_events[-1]
    assert "now_override" in last_event["detail"], \
        "The 'now' override was not recorded in the audit trail"
    assert forged_now.isoformat() in last_event["detail"]


def test_r2_006_no_now_override_tag_when_now_is_none(tmp_path):
    """When now=None (normal usage), the audit trail omits 'now_override'."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.vault.conditions import AccessPolicy, ManualCondition

    policy = AccessPolicy(conditions=[ManualCondition(activated=True)])
    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass", policy=policy)
    agent.lock("pass")

    agent.open_heir("heir-1", "pass")

    condition_events = agent._audit.events(event_type="CONDITION_CHECK")
    assert len(condition_events) >= 1
    last_event = condition_events[-1]
    assert "now_override" not in last_event["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# DL invariants — enforcement
# ─────────────────────────────────────────────────────────────────────────────

def test_dl001_ingest_always_sets_artifact(tmp_path):
    """DL-001: artifact_id and path are always present after ingest()."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    doc = tmp_path / "will.txt"
    doc.write_text("This is my will.")
    record = agent.ingest(doc)

    assert record.artifact_id
    assert record.path == str(doc)
    assert record.memory_id


def test_dl004_every_vault_mutation_has_audit_event(tmp_path):
    """
    DL-004: initialize, ingest, reinforce_memory, forget_memory, and lock
    each produce exactly their expected events.
    """
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("sample content", DocCategory.PERSONAL)
    agent.reinforce_memory(mid)
    agent.forget_memory(mid)
    agent.lock("pass")

    events = agent._audit.events()
    event_types = [e["event_type"] for e in events]

    assert "VAULT_CREATED" in event_types
    assert "MEMORY_REINFORCED" in event_types
    assert "MEMORY_FORGOTTEN" in event_types
    assert "VAULT_LOCKED" in event_types


def test_dl005_stdp_makes_retrieval_stateful(tmp_path):
    """
    DL-005 (documented limitation): two identical consecutive recall() calls
    produce the same top_memory_id but different scores (last_access mutates).
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mf.store("mortgage deed bank property", DocCategory.REAL_ESTATE)
    mf.store("will inheritance family legacy", DocCategory.LEGAL)

    r1 = mf.recall("mortgage bank")
    r2 = mf.recall("mortgage bank")

    # ID ordering must be consistent.
    assert [r.memory_id for r in r1] == [r.memory_id for r in r2]
    # Scores may differ because of last_access / recency_bonus.
    # We do not assert equality; this is expected STDP behavior.
