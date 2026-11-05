"""
tests/test_security_r10.py
===========================
Red-team round R10. Three findings, reproduced and fixed:

R10-001 (High, correctness) - false "no information" from an inferred
category. `QueryEngine.query` used the category it *inferred from the
question* as a hard recall filter. The question classifier and the document
classifier disagree on real inputs: "Where is the apartment deed?" infers
`legal`, while a deed without legal vocabulary is stored as `real_estate`.
The core then answered "No relevant information found" for a record that
exists - the worst possible answer for an heir. C-001 (R3) accepted that an
*explicit* category filter is strict; it did not cover an inferred one.
Fix: when the inferred category yields nothing, the core re-runs recall
without the filter and says so in the answer. Explicit category recall
stays strict.

R10-002 (Medium) - variant of R7-002. `category` and `artifact` live in
cleartext in memory.db and drive what an heir sees (category-filtered
recall; the location shown in answers). Rewriting either one hid a record
from a category query or pointed the heir to a fake location, while
`verify_memory_integrity` reported ok=True. Fix: both columns are compared
with the sealed vault index. No code path updates them after insert.

R10-003 (Low) - `Studio.demo()` replaced any open session, including an heir
session, which came back as `role: owner` of the demo workspace. Fix: the
safe sample opens only when no private session is open.
"""
from __future__ import annotations

import sqlite3

import pytest

from continuum_web import server
from legacy.agent.query_engine import QueryEngine
from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField


PASSPHRASE = "a-long-test-passphrase"
DEED = "Property deed for the apartment. The original is in the blue archival folder."


@pytest.fixture()
def studio(tmp_path):
    instance = server.Studio(tmp_path / "ws")
    instance.create("owner@example.test", PASSPHRASE)
    instance.capture("Deed", DEED, [])
    yield instance
    if instance.agent is not None:
        instance.lock()


# --- R10-001: inferred category must not produce a false negative --------------


def test_r10_001_reproduction_preconditions_hold(studio):
    """Pin the disagreement that produced the false negative, so this test
    file keeps exercising the fallback if either classifier changes."""
    engine = QueryEngine(studio.agent._memory)
    stored = studio.agent._index.artifacts[0]["category"]
    inferred = engine.analyze("Where is the apartment deed?").detected_category
    assert inferred is not None and inferred.value != stored


def test_r10_001_existing_record_is_found_despite_category_mismatch(studio):
    response = QueryEngine(studio.agent._memory).query("Where is the apartment deed?", top_k=6)
    assert response.results, response.answer
    assert "No relevant information found" not in response.answer
    assert any("blue archival folder" in r.content for r in response.results)


def test_r10_001_fallback_is_stated_not_hidden(studio):
    response = QueryEngine(studio.agent._memory).query("Where is the apartment deed?", top_k=6)
    assert "No match in the 'legal' category" in response.answer
    assert response.category_filter is None
    assert "Detected category: legal" not in response.answer


def test_r10_001_studio_ask_returns_sources(studio):
    result = studio.ask("Where is the apartment deed?")
    assert result["sources"]
    assert result["category"] is None


def test_r10_001_matching_category_still_ranks_first(tmp_path):
    """The inferred category no longer filters (R11-001), but a record in it
    that matches best is still selected first."""
    memory = MemoryField(tmp_path / "m.db")
    memory.store("medical history diagnosis penicillin allergy", DocCategory.MEDICAL)
    memory.store("medical insurance invoice paid by bank transfer", DocCategory.FINANCIAL)
    response = QueryEngine(memory).query("medical history diagnosis", top_k=6)
    assert response.results[0].category == DocCategory.MEDICAL


def test_r10_001_truly_absent_information_is_still_reported(tmp_path):
    """Negative control: the fallback never invents evidence."""
    memory = MemoryField(tmp_path / "m.db")
    memory.store("Photos from the coastal trip are on the family drive.", DocCategory.PERSONAL)
    response = QueryEngine(memory).query("Where is the apartment deed?", top_k=6)
    assert response.results == []
    assert "No relevant information found" in response.answer


def test_r10_001_explicit_category_recall_remains_strict(tmp_path):
    """C-001 is unchanged: an explicit filter on MemoryField is strict."""
    memory = MemoryField(tmp_path / "m.db")
    mid = memory.store("mortgage deed property real estate bank", DocCategory.LEGAL)
    filtered = memory.recall("mortgage property", category=DocCategory.REAL_ESTATE)
    assert not any(r.memory_id == mid for r in filtered)


# --- R10-002: cleartext category / artifact tampering ------------------------


def _tamper(studio, column, value):
    with sqlite3.connect(studio.workspace / "memory.db") as conn:
        conn.execute(f"UPDATE memories SET {column}=?", (value,))


def test_r10_002_clean_workspace_passes(studio):
    assert studio.agent.verify_memory_integrity()["ok"] is True


def test_r10_002_category_flip_is_detected(studio):
    stored = studio.agent._index.artifacts[0]["category"]
    flipped = "personal" if stored != "personal" else "legal"
    _tamper(studio, "category", flipped)
    report = studio.agent.verify_memory_integrity()
    assert report["ok"] is False
    assert any("category" in error for error in report["errors"])


def test_r10_002_artifact_location_rewrite_is_detected(studio):
    _tamper(studio, "artifact", "/elsewhere/deed-moved-to-locker-17.txt")
    report = studio.agent.verify_memory_integrity()
    assert report["ok"] is False
    assert any("location" in error for error in report["errors"])


def test_r10_002_studio_dashboard_reports_the_tamper(studio):
    _tamper(studio, "category", "personal")
    assert studio.snapshot()["integrity"] is False


# --- R10-003: demo must not replace an open session --------------------------


def test_r10_003_demo_refuses_while_owner_session_is_open(studio):
    with pytest.raises(ValueError, match="Lock"):
        studio.demo()
    assert studio.role == "owner"
    assert studio.snapshot()["workspace_mode"] == "private"


def test_r10_003_demo_refuses_while_heir_session_is_open(tmp_path):
    from datetime import datetime, timezone

    instance = server.Studio(tmp_path / "ws")
    instance.create(
        "owner@example.test",
        PASSPHRASE,
        inactivity_days=1,
        inactivity_last_activity=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    instance.lock()
    instance.unlock_heir("heir-one", PASSPHRASE)
    with pytest.raises(ValueError, match="Lock"):
        instance.demo()
    assert instance.role == "heir"
    instance.lock()


def test_r10_003_demo_still_works_from_locked_state_and_can_be_reopened(tmp_path):
    instance = server.Studio(tmp_path / "ws")
    assert instance.demo()["workspace_mode"] == "safe_demo"
    # Re-running the sample from the sample itself stays allowed.
    assert instance.demo()["workspace_mode"] == "safe_demo"
    instance.lock()
