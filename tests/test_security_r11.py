"""
tests/test_security_r11.py
===========================
Red-team round R11.

R11-001 (High, correctness) - variant of R10-001 that its fix missed. The
R10 fallback dropped the inferred category only when it yielded *nothing*.
When the inferred category held any weak match, the strongest record in
another category was never considered: "safe deposit box key bank" infers
`financial`, six unrelated bank notes filled the results, and the record
that actually answers the question (stored as `unknown`, score 0.93 vs 0.15)
was absent from every source list. Fix: the inferred category is a hint,
never a filter. One unfiltered recall selects by relevance; the category
only breaks exact score ties and labels the answer when every result
belongs to it.

C9 (closed, Low) - ranking through cleartext `state`/`last_access`. Promoting
six decoys to REINFORCED with fresh recency moved them from 0.153 to 0.205;
the real match stayed first at 0.876. The 1.5x multiplier can reorder only
near-ties, so it cannot hide a clear best match. Not fixed: per-id promotion
attribution would flag every workspace consolidated before such logging.
The test below pins that bound so a future scoring change re-opens it.
"""
from __future__ import annotations

import sqlite3
import time

import pytest

from continuum_web import server
from legacy.agent.query_engine import QueryEngine
from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField


PASSPHRASE = "a-long-test-passphrase"
QUESTION = "safe deposit box key bank"
TARGET = "Safe deposit box key: the bank safe deposit box key is in the kitchen drawer."


@pytest.fixture()
def studio(tmp_path):
    instance = server.Studio(tmp_path / "ws")
    instance.create("owner@example.test", PASSPHRASE)
    target = instance.capture("Target", TARGET, [])["record"]
    notes = [
        instance.capture(f"Note {i}", f"Bank note {i}: the bank statement was archived.", [])[
            "record"
        ]
        for i in range(6)
    ]
    yield instance, target, notes
    if instance.agent is not None:
        instance.lock()


def test_r11_001_reproduction_preconditions_hold(studio):
    """Inferred category has weak matches; the best match lies outside it."""
    instance, target, notes = studio
    analysis = QueryEngine(instance.agent._memory).analyze(QUESTION)
    assert analysis.detected_category is not None
    assert target["category"] != analysis.detected_category.value
    assert all(note["category"] == analysis.detected_category.value for note in notes)


def test_r11_001_strongest_record_is_selected_first(studio):
    instance, target, _notes = studio
    response = QueryEngine(instance.agent._memory).query(QUESTION, top_k=6)
    assert response.results
    assert response.results[0].memory_id == target["memory_id"]


def test_r11_001_studio_ask_shows_the_answering_source(studio):
    instance, _target, _notes = studio
    sources = instance.ask(QUESTION)["sources"]
    assert "kitchen drawer" in sources[0]["excerpt"]


def test_r11_001_mixed_results_are_not_labelled_as_one_category(studio):
    instance, _target, _notes = studio
    response = QueryEngine(instance.agent._memory).query(QUESTION, top_k=6)
    assert response.category_filter is None
    assert "Detected category" not in response.answer


def test_r11_001_category_breaks_exact_ties_only(tmp_path):
    memory = MemoryField(tmp_path / "m.db")
    memory.store("medical history diagnosis penicillin allergy", DocCategory.MEDICAL)
    memory.store("medical insurance invoice paid by bank transfer", DocCategory.FINANCIAL)
    response = QueryEngine(memory).query("medical history diagnosis", top_k=6)
    assert response.results[0].category == DocCategory.MEDICAL


def test_r11_001_single_category_results_keep_their_label(tmp_path):
    memory = MemoryField(tmp_path / "m.db")
    memory.store("medical history diagnosis penicillin allergy", DocCategory.MEDICAL)
    memory.store("medical lab results diagnosis 2021", DocCategory.MEDICAL)
    response = QueryEngine(memory).query("medical history diagnosis", top_k=6)
    assert response.category_filter == DocCategory.MEDICAL


def test_r11_001_recall_runs_once_per_query(tmp_path, monkeypatch):
    """Recall mutates STDP state; the fix must not apply it twice."""
    memory = MemoryField(tmp_path / "m.db")
    memory.store("Property deed for the apartment in the blue folder.", DocCategory.REAL_ESTATE)
    calls = []
    original = memory.recall
    monkeypatch.setattr(memory, "recall", lambda *a, **k: calls.append(k) or original(*a, **k))
    QueryEngine(memory).query("Where is the apartment deed?", top_k=6)
    assert len(calls) == 1
    assert calls[0].get("category") is None


def test_c9_state_promotion_cannot_displace_a_clear_best_match(studio):
    instance, target, notes = studio
    with sqlite3.connect(instance.workspace / "memory.db") as conn:
        for note in notes:
            conn.execute(
                "UPDATE memories SET state='REINFORCED', last_access=? WHERE memory_id=?",
                (time.time(), note["memory_id"]),
            )
        conn.execute(
            "UPDATE memories SET last_access=0 WHERE memory_id=?", (target["memory_id"],)
        )
    response = QueryEngine(instance.agent._memory).query(QUESTION, top_k=6)
    assert response.results[0].memory_id == target["memory_id"]
