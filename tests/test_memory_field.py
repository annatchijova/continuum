"""
tests/test_memory_field.py
===========================
Tests for the memory field with STDP and ternary states.
"""
import time

import pytest

from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField, MemoryState


@pytest.fixture
def mem(tmp_path):
    return MemoryField(tmp_path / "mem.db")


# Basic storage and recall.

def test_store_returns_id(mem):
    mid = mem.store("contract mortgage bank account", category=DocCategory.LEGAL)
    assert isinstance(mid, str)
    assert len(mid) == 36  # UUID4


def test_recall_finds_stored(mem):
    mem.store("contract mortgage bank deed", category=DocCategory.LEGAL,
              artifact="/docs/contract.pdf")
    results = mem.recall("contract mortgage")
    assert len(results) > 0


def test_recall_by_category(mem):
    mem.store("Netflix suscripcion renovacion automatica cargo mensual",
              category=DocCategory.SUBSCRIPTION)
    mem.store("diagnosis hipertension patient clinica medico",
              category=DocCategory.MEDICAL)
    results = mem.recall("suscripcion", category=DocCategory.SUBSCRIPTION)
    for r in results:
        assert r.category == DocCategory.SUBSCRIPTION


def test_recall_empty_returns_empty(mem):
    results = mem.recall("nada that no exista in the field empty")
    assert results == []


def test_recall_does_not_treat_recency_as_evidence_for_an_absent_fact(mem):
    mem.store(
        "Medication schedule lists a penicillin allergy and a morning refill.",
        category=DocCategory.MEDICAL,
    )
    mem.store(
        "The pet food is in the lower kitchen cupboard.",
        category=DocCategory.PERSONAL,
    )

    assert mem.recall("What is my blood type?") == []


def test_recall_ignores_orphan_apostrophe_fragment_as_evidence(mem):
    # FIX: "What's" tokenizes into "what" + a bare "s" fragment. That "s" is
    # not a stopword, so it used to survive as an "evidence term" and match
    # any document containing an apostrophe (e.g. "Dr. Lee's", "Milo's"),
    # letting unrelated documents pass the relevance filter.
    mem.store(
        "Dr. Lee's contact info: direct line, mentions penicillin allergy.",
        category=DocCategory.MEDICAL,
    )
    mem.store(
        "Milo's food is in the lower kitchen cupboard.",
        category=DocCategory.PERSONAL,
    )

    assert mem.recall("What's my blood type?") == []


def test_recall_updates_recall_count(tmp_path):
    mem = MemoryField(tmp_path / "m.db")
    mid = mem.store("will notarial deed contract inheritance",
                    category=DocCategory.LEGAL)
    mem.recall("will notarial")
    # Stored content is normalized and hashed consistently.
    import sqlite3
    conn = sqlite3.connect(tmp_path / "m.db")
    row = conn.execute(
        "SELECT recall_count FROM memories WHERE memory_id=?", (mid,)
    ).fetchone()
    conn.close()
    assert row[0] >= 1


# Memory state transitions.

def test_initial_state_is_neutral(tmp_path):
    mem = MemoryField(tmp_path / "m.db")
    mid = mem.store("contract legal deed", category=DocCategory.LEGAL)
    import sqlite3
    conn = sqlite3.connect(tmp_path / "m.db")
    row = conn.execute(
        "SELECT state FROM memories WHERE memory_id=?", (mid,)
    ).fetchone()
    conn.close()
    assert row[0] == MemoryState.NEUTRAL.value


def test_reinforce_changes_state(tmp_path):
    mem = MemoryField(tmp_path / "m.db")
    mid = mem.store("seguro of vida poliza beneficiarios", category=DocCategory.FINANCIAL)
    mem.reinforce(mid)
    import sqlite3
    conn = sqlite3.connect(tmp_path / "m.db")
    row = conn.execute(
        "SELECT state FROM memories WHERE memory_id=?", (mid,)
    ).fetchone()
    conn.close()
    assert row[0] == MemoryState.REINFORCED.value


def test_forget_changes_state(tmp_path):
    mem = MemoryField(tmp_path / "m.db")
    mid = mem.store("irrelevant temporary note", category=DocCategory.PERSONAL)
    mem.forget(mid)
    import sqlite3
    conn = sqlite3.connect(tmp_path / "m.db")
    row = conn.execute(
        "SELECT state FROM memories WHERE memory_id=?", (mid,)
    ).fetchone()
    conn.close()
    assert row[0] == MemoryState.FORGOTTEN.value


def test_forgotten_not_recalled(mem):
    mid = mem.store("note that will be forgotten contract", category=DocCategory.PERSONAL)
    mem.forget(mid)
    results = mem.recall("note forgotten contract")
    ids = [r.memory_id for r in results]
    assert mid not in ids


def test_reinforced_scores_higher(tmp_path):
    """a memory REINFORCED must tener mayor score in recall that a NEUTRAL similar."""
    mem = MemoryField(tmp_path / "m.db")
    mid_reinforced = mem.store(
        "contract deed property real estate notarial legal",
        category=DocCategory.LEGAL,
        state=MemoryState.REINFORCED,
    )
    mid_neutral = mem.store(
        "contract deed property real estate notarial legal copy",
        category=DocCategory.LEGAL,
        state=MemoryState.NEUTRAL,
    )
    results = mem.recall("contract deed legal")
    score_map = {r.memory_id: r.final_score for r in results}

    assert mid_reinforced in score_map
    assert mid_neutral in score_map
    assert score_map[mid_reinforced] >= score_map[mid_neutral]


# Synapse and reinforcement behavior.

def test_stdp_creates_synaptic_links(tmp_path):
    """Almacenar multiples memories of the same categoria crea links STDP."""
    mem = MemoryField(tmp_path / "m.db")
    mem.store("contract mortgage bank real estate", category=DocCategory.FINANCIAL)
    mem.store("inversion fondos seguro of vida", category=DocCategory.FINANCIAL)
    import sqlite3
    conn = sqlite3.connect(tmp_path / "m.db")
    count = conn.execute("SELECT COUNT(*) FROM synaptic_links").fetchone()[0]
    conn.close()
    assert count > 0


# Recall and filtering behavior.

def test_stats_empty(mem):
    stats = mem.stats()
    assert stats["total"] == 0


def test_stats_after_inserts(mem):
    mem.store("contract legal", category=DocCategory.LEGAL)
    mem.store("seguro financiero", category=DocCategory.FINANCIAL)
    stats = mem.stats()
    assert stats["total"] == 2
    assert "by_category" in stats


# Database integrity behavior.

def test_persistence_across_instances(tmp_path):
    db = tmp_path / "persist.db"
    m1 = MemoryField(db)
    mid = m1.store("will inheritance notarial deed",
                   category=DocCategory.LEGAL)

    m2 = MemoryField(db)
    results = m2.recall("will")
    ids = [r.memory_id for r in results]
    assert mid in ids
