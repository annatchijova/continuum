"""
tests/test_security_r7.py
==========================
Red-team round R7. Two findings, both CONFIRMED BY INDUCTION and fixed:

R7-001 (High) - multi-heir lockout. `AccessPolicy.evaluate` applied the ONE
presented key against EVERY `HeirKeyCondition`; under the default AND
operator, registering a second heir's key made the policy unsatisfiable for
ALL heirs (`all([...True, False])`). Two heirs with a key would lock each
other out. Fix: HeirKeyCondition entries are OR-combined among themselves,
and that group participates in the global operator.

R7-002 (Medium) - state-suppression outside the perimeter. A memory's
`state` governs its recall visibility (`state != 'FORGOTTEN'`) but is
cleartext and unauthenticated, even with `encrypt-db`. An attacker with
write access to memory.db could flip an indexed memory to FORGOTTEN: the
heir stops seeing it, and `verify_memory_integrity` reported `ok=True`
(it only checked content, not `state`). Fix: the check cross-references
each indexed FORGOTTEN memory against MEMORY_FORGOTTEN audit events; a
suppression with no audit backing is tampering.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.conditions import (
    AccessPolicy,
    ConditionOperator,
    DateCondition,
    HeirKeyCondition,
    InactivityCondition,
)

PASS = "pw"
# Inactivity already satisfied (0 days since a date far in the past).
_MET_INACTIVITY = InactivityCondition(days=0, last_activity_iso="2000-01-01T00:00:00+00:00")


# -----------------------------------------------------------------------------
# R7-001 - multi-heir lockout
# -----------------------------------------------------------------------------

def _agent_with_two_heir_keys(tmp_path, operator=ConditionOperator.AND):
    agent = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    policy = AccessPolicy([_MET_INACTIVITY], operator=operator)
    agent.initialize(PASS, policy=policy)
    agent.add_heir("h1", "Daughter")
    key_a = agent.register_heir_key("h1")
    agent.add_heir("h2", "Son")
    key_b = agent.register_heir_key("h2")
    agent.lock(PASS)
    return key_a, key_b


def test_r7_001_two_heirs_each_key_grants_access(tmp_path):
    """With two keyed heirs (AND + satisfied inactivity), EACH gets in with
    THEIR OWN key. Before the fix, both were locked out."""
    key_a, key_b = _agent_with_two_heir_keys(tmp_path)

    a = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    assert a.open_heir("h1", PASS, heir_key=key_a) is True

    b = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    assert b.open_heir("h2", PASS, heir_key=key_b) is True


def test_r7_001_wrong_key_still_denied(tmp_path):
    """The group OR does not weaken security: a wrong key that matches NO
    heir is still denied."""
    _agent_with_two_heir_keys(tmp_path)
    a = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    assert a.open_heir("h1", PASS, heir_key="made-up-key") is False


def test_r7_001_and_still_requires_other_conditions(tmp_path):
    """The key group participates in the global AND: if inactivity is NOT
    satisfied, the correct key alone is not enough (defense in depth)."""
    agent = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    # Inactivity NOT satisfied: 3650 days from today is not possible yet.
    not_met = InactivityCondition(
        days=3650, last_activity_iso=datetime.now(timezone.utc).isoformat()
    )
    agent.initialize(PASS, policy=AccessPolicy([not_met]))
    agent.add_heir("h1", "Daughter")
    key_a = agent.register_heir_key("h1")
    agent.lock(PASS)
    a = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    assert a.open_heir("h1", PASS, heir_key=key_a) is False


def test_r7_001_unit_or_group_semantics():
    """Unit: two HeirKeyCondition entries + one temporal condition, AND
    operator. Either key + the temporal condition -> True."""
    ka = HeirKeyCondition.create("a", "secret-a")
    kb = HeirKeyCondition.create("b", "secret-b")
    pol = AccessPolicy([_MET_INACTIVITY, ka, kb], operator=ConditionOperator.AND)
    assert pol.evaluate(heir_key="secret-a") is True
    assert pol.evaluate(heir_key="secret-b") is True
    assert pol.evaluate(heir_key="secret-c") is False
    # Only keys (no other conditions): the group IS the policy.
    only_keys = AccessPolicy([ka, kb], operator=ConditionOperator.AND)
    assert only_keys.evaluate(heir_key="secret-a") is True
    assert only_keys.evaluate(heir_key="nothing") is False


# -----------------------------------------------------------------------------
# R7-002 - suppression via a `state` flip invisible to the integrity check
# -----------------------------------------------------------------------------

def _ingest_and_persist(tmp_path, content="The will names Maria as heir."):
    agent = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    agent.initialize(PASS)
    f = tmp_path / "doc.txt"
    f.write_text(content)
    rec = agent.ingest(f)
    agent.lock(PASS)  # persists the index into the vault
    return rec.memory_id


def _flip_state(tmp_path, memory_id, state="FORGOTTEN"):
    con = sqlite3.connect(tmp_path / "memory.db")
    con.execute("UPDATE memories SET state=? WHERE memory_id=?", (state, memory_id))
    con.commit()
    con.close()


def test_r7_002_out_of_band_suppression_detected(tmp_path):
    """A state->FORGOTTEN flip with no audit event = detected suppression."""
    mid = _ingest_and_persist(tmp_path)

    ok0 = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    ok0.open_owner(PASS)
    assert ok0.verify_memory_integrity()["ok"] is True
    ok0.lock(PASS)

    _flip_state(tmp_path, mid)

    ag = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    ag.open_owner(PASS)
    # The heir no longer sees it...
    assert ag.query("will", actor="h1") == []
    # ...and the integrity check now DETECTS it (previously: ok=True).
    result = ag.verify_memory_integrity()
    assert result["ok"] is False
    assert any("FORGOTTEN with no audit event" in e for e in result["errors"])


def test_r7_002_legitimate_forget_not_flagged(tmp_path):
    """forget_memory (manual, audit-attributable) is NOT a false positive."""
    agent = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    agent.initialize(PASS)
    f = tmp_path / "doc.txt"
    f.write_text("Old note about a closed account.")
    rec = agent.ingest(f)
    agent.forget_memory(rec.memory_id)  # legitimate forget -> MEMORY_FORGOTTEN
    agent.lock(PASS)

    agent.open_owner(PASS)
    assert agent.verify_memory_integrity()["ok"] is True


def test_r7_002_consolidation_forget_not_flagged(tmp_path):
    """Consolidation records its own forgetting by memory_id: merged
    duplicates (FORGOTTEN) are not false positives."""
    agent = LegacyAgent(data_dir=tmp_path, owner_id="owner", hmac_key=b"")
    agent.initialize(PASS)
    # Near-identical content (high Jaccard similarity) but a different
    # content_hash, so ingest creates TWO memories and consolidation merges one.
    variants = [
        "Lease agreement for the house at 123 Main Street signed January 2019.",
        "Lease agreement for the house at 123 Main Street signed January 2019 revA.",
    ]
    for i, text in enumerate(variants):
        f = tmp_path / f"c{i}.txt"
        f.write_text(text)
        agent.ingest(f, notes=f"copy {i}")
    report = agent.consolidate(similarity_threshold=0.5)
    agent.lock(PASS)

    # At least one merge-forget happened, and it was recorded by id.
    assert report.forgotten_ids, "consolidation should have forgotten the duplicate"

    agent.open_owner(PASS)
    assert agent.verify_memory_integrity()["ok"] is True
