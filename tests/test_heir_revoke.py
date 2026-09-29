"""
tests/test_heir_revoke.py
==========================
revoke_heir + knowledge extraction during ingest.
"""
from __future__ import annotations

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.knowledge.extractor import KnowledgeDomain

PASS = "pw"


def test_revoked_heir_denied_even_with_valid_key(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.add_heir("h1", "Primary heir")
    secret = agent.register_heir_key("h1")
    assert agent.revoke_heir("h1") is True
    agent.lock(PASS)

    heir = LegacyAgent(tmp_path, "owner")
    assert heir.open_heir("h1", PASS, heir_key=secret) is False
    denied = [e for e in heir._audit.events(event_type="ACCESS_DENIED")]
    assert any("revoked" in (e["detail"] or "") for e in denied)


def test_revoke_removes_key_condition_but_keeps_history(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.add_heir("h1", "Owner")
    agent.register_heir_key("h1")
    agent.revoke_heir("h1")

    conds = agent._index.policy["conditions"]
    assert not any(
        c.get("type") == "heir_key" and c.get("heir_id") == "h1" for c in conds
    )
    h = next(h for h in agent._index.heirs if h["heir_id"] == "h1")
    assert h.get("revoked_at")
    assert "HEIR_REVOKED" in [e["event_type"] for e in agent._audit.events()]


def test_other_heirs_unaffected_by_revocation(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.add_heir("h1", "Owner")
    agent.add_heir("h2", "Maria")
    s1 = agent.register_heir_key("h1")
    s2 = agent.register_heir_key("h2")
    agent.revoke_heir("h1")
    agent.lock(PASS)

    heir = LegacyAgent(tmp_path, "owner")
    assert heir.open_heir("h2", PASS, heir_key=s2) is True
    heir2 = LegacyAgent(tmp_path, "owner")
    assert heir2.open_heir("h1", PASS, heir_key=s1) is False


def test_revoke_unknown_heir_returns_false(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    assert agent.revoke_heir("fantasma") is False


def test_revoked_heir_excluded_from_summary_and_guide(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.add_heir("h1", "Owner")
    agent.add_heir("h2", "Maria")
    agent.revoke_heir("h1")

    assert agent.summary("owner")["heirs"] == ["Maria"]
    guide = agent.heir_guide(actor="owner")
    assert "Maria" in guide and "Primary heir" not in guide


def test_ingest_with_knowledge_extraction(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)
    src = tmp_path / "medical_notes.txt"
    src.write_text(
        "treatment protocol for patients diagnosed with hypertension: "
        "the initial clinical treatment uses graduated doses and patient "
        "follow-up every three weeks.",
        encoding="utf-8",
    )
    agent.ingest(src, extract_knowledge=True)

    entries = agent.knowledge.search("treatment patients")
    assert entries and entries[0].domain == KnowledgeDomain.MEDICINE
    assert entries[0].source_path == str(src)
    assert "KNOWLEDGE_EXTRACTED" in [
        e["event_type"] for e in agent._audit.events()
    ]
    assert (tmp_path / "data" / "knowledge.db").exists()


def test_ingest_without_flag_does_not_create_knowledge_db(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)
    src = tmp_path / "note.txt"
    src.write_text("an ordinary note with enough content for this test",
                   encoding="utf-8")
    agent.ingest(src)
    assert not (tmp_path / "data" / "knowledge.db").exists()


def test_ingest_knowledge_skips_short_text_silently(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)
    src = tmp_path / "short.txt"
    src.write_text("very short", encoding="utf-8")
    agent.ingest(src, extract_knowledge=True)
    assert "KNOWLEDGE_EXTRACTED" not in [
        e["event_type"] for e in agent._audit.events()
    ]
