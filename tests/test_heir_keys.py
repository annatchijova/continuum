"""
tests/test_heir_keys.py
========================
register_heir_key + consolidate: heir management and memory maintenance
through LegacyAgent, with an audit trail.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.conditions import (
    AccessPolicy,
    ConditionOperator,
    HeirKeyCondition,
    InactivityCondition,
)

PASS = "pw"


def test_register_key_grants_access_with_correct_key(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.add_heir("h1", "Olga")
    secret = agent.register_heir_key("h1")
    agent.lock(PASS)

    heir = LegacyAgent(tmp_path, "owner")
    assert heir.open_heir("h1", PASS, heir_key=secret) is True


def test_wrong_key_is_denied(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.register_heir_key("h1")
    agent.lock(PASS)

    heir = LegacyAgent(tmp_path, "owner")
    assert heir.open_heir("h1", PASS, heir_key="key-incorrect") is False


def test_secret_is_never_persisted_in_plaintext(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    secret = agent.register_heir_key("h1")
    agent.lock(PASS)

    vault_bytes = (tmp_path / "legacy.vault").read_bytes()
    assert secret.encode() not in vault_bytes
    for ev in agent._audit.events():
        assert secret not in (ev.get("detail") or "")
        assert secret not in (ev.get("artifact") or "")
    reopened = LegacyAgent(tmp_path, "owner")
    reopened.open_owner(PASS)
    conds = reopened._index.policy["conditions"]
    assert conds[0]["type"] == "heir_key"
    assert "key_hash" in conds[0] and secret not in str(conds[0])


def test_register_key_appends_to_existing_policy_with_and(tmp_path):
    """With an existing AND policy, the key alone is insufficient.
    Defense in depth still requires the inactivity condition."""
    recent = datetime.now(timezone.utc).isoformat()
    policy = AccessPolicy([InactivityCondition(days=90, last_activity_iso=recent)])
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS, policy=policy)
    secret = agent.register_heir_key("h1")
    agent.lock(PASS)

    heir = LegacyAgent(tmp_path, "owner")
    assert heir.open_heir("h1", PASS, heir_key=secret) is False  # AND: inactivity missing

    future = datetime.now(timezone.utc) + timedelta(days=91)
    heir2 = LegacyAgent(tmp_path, "owner")
    assert heir2.open_heir("h1", PASS, heir_key=secret, now=future) is True


def test_register_key_audits(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.register_heir_key("h1")
    assert "HEIR_KEY_REGISTERED" in [
        e["event_type"] for e in agent._audit.events()
    ]


def test_register_key_requires_unlocked(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        agent.register_heir_key("h1")


def test_consolidate_merges_duplicates_and_audits(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)

    base = "The house purchase contract was signed before a notary in March."
    from legacy.ingestion.doc_types import DocCategory
    agent._memory.store(base, DocCategory.LEGAL)
    agent._memory.store(base + " pasado", DocCategory.LEGAL)

    report = agent.consolidate()
    assert report.duplicates_merged >= 1
    assert not report.errors
    assert "MEMORY_CONSOLIDATED" in [
        e["event_type"] for e in agent._audit.events()
    ]


def test_consolidate_requires_unlocked(tmp_path):
    agent = LegacyAgent(tmp_path, "owner")
    agent.initialize(PASS)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        agent.consolidate()
