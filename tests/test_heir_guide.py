"""
tests/test_heir_guide.py
=========================
Heir Guide: deterministic markdown ordered by priority.
"""
from __future__ import annotations

import pytest

from legacy.agent.heir_guide import build_guide
from legacy.agent.memory_agent import LegacyAgent

PASS = "pw"

_INDEX = {
    "owner_id": "anna",
    "created_at": "2026-01-01T00:00:00+00:00",
    "last_updated": "2026-07-01T00:00:00+00:00",
    "artifacts": [
        {
            "artifact_id": "a1", "path": "/docs/foto.jpg", "filename": "foto.jpg",
            "category": "media", "content_hash": "c" * 64,
            "classification_confidence": "LOW", "memory_id": "m1",
            "ingested_at": "2026-02-01T00:00:00+00:00", "tags": [], "notes": "",
        },
        {
            "artifact_id": "a2", "path": "/docs/testamento.pdf",
            "filename": "testamento.pdf", "category": "legal",
            "content_hash": "a" * 64, "classification_confidence": "HIGH",
            "memory_id": "m2", "ingested_at": "2026-02-01T00:00:00+00:00",
            "tags": ["urgent"], "notes": "original at the notary office",
        },
        {
            "artifact_id": "a3", "path": "/docs/netflix.txt",
            "filename": "netflix.txt", "category": "subscription",
            "content_hash": "b" * 64, "classification_confidence": "MEDIUM",
            "memory_id": "m3", "ingested_at": "2026-02-01T00:00:00+00:00",
            "tags": [], "notes": "",
        },
    ],
    "heirs": [{"heir_id": "h1", "display_name": "Olga", "email": ""}],
    "policy": None,
    "notes": "",
}

_TS = "2026-07-07T12:00:00+00:00"


def test_guide_is_deterministic():
    g1 = build_guide(_INDEX, generated_at=_TS)
    g2 = build_guide(_INDEX, generated_at=_TS)
    assert g1 == g2


def test_categories_ordered_by_priority():
    guide = build_guide(_INDEX, generated_at=_TS)
    # legal (priority 1) before subscription (2), before media (4)
    assert guide.index("[1] legal") < guide.index("[2] subscription") < guide.index("[4] media")


def test_guide_content_fields():
    guide = build_guide(_INDEX, generated_at=_TS)
    assert "testamento.pdf" in guide
    assert "original at the notary office" in guide  # owner note
    assert "urgent" in guide                         # tags
    assert "Olga" in guide                            # heirs
    assert "verify_legacy.py" in guide                # verification instructions
    assert ("a" * 16) + "…" in guide                  # truncated hash


def test_guide_marks_archived_artifacts():
    guide = build_guide(_INDEX, generated_at=_TS, archived_hashes=["a" * 64])
    line = next(l for l in guide.splitlines() if "testamento.pdf" in l)
    assert "🔒" in line
    other = next(l for l in guide.splitlines() if "foto.jpg" in l)
    assert "🔒" not in other


def test_guide_never_contains_passphrase_or_key_material():
    guide = build_guide(_INDEX, generated_at=_TS)
    for forbidden in ("passphrase", "password", "credential:"):
        assert forbidden not in guide.lower().replace("credential secrets", "")


def test_empty_index():
    empty = dict(_INDEX, artifacts=[], heirs=[])
    guide = build_guide(empty, generated_at=_TS)
    assert "contains no artifacts" in guide


def test_agent_heir_guide_audits(tmp_path):
    agent = LegacyAgent(tmp_path, "anna")
    agent.initialize(PASS)
    src = tmp_path / "carta.txt"
    src.write_text("Dear child: this is a personal letter for you.", encoding="utf-8")
    agent.ingest(src)

    guide = agent.heir_guide(actor="h1")
    assert "carta.txt" in guide
    assert "GUIDE_GENERATED" in [e["event_type"] for e in agent._audit.events()]


def test_agent_heir_guide_requires_unlocked(tmp_path):
    agent = LegacyAgent(tmp_path, "anna")
    agent.initialize(PASS)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        agent.heir_guide(actor="h1")
