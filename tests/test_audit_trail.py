"""
tests/test_audit_trail.py
==========================
Tests of the audit trail with hash chain.
"""
import pytest
from pathlib import Path

from legacy.core.audit_trail import AuditTrail
from legacy.core.hash_chain import verify_chain, ChainLink, GENESIS_HASH


@pytest.fixture
def trail(tmp_path):
    return AuditTrail(tmp_path / "audit.db", hmac_key=b"")


@pytest.fixture
def trail_hmac(tmp_path):
    return AuditTrail(tmp_path / "audit_hmac.db", hmac_key=b"x" * 32)


# Implementation note.
# Implementation note.
# Implementation note.

def test_append_and_read(trail):
    trail.append("VAULT_CREATED", actor="owner_1")
    events = trail.events()
    assert len(events) == 1
    assert events[0]["event_type"] == "VAULT_CREATED"
    assert events[0]["actor"] == "owner_1"
    assert events[0]["seq"] == 1


def test_multiple_events(trail):
    trail.append("VAULT_CREATED", actor="owner_1")
    trail.append("ARTIFACT_INGESTED", actor="owner_1", artifact="/path/to/doc.pdf")
    trail.append("QUERY", actor="heir_1", detail="where is the house deed?")
    events = trail.events()
    assert len(events) == 3
    assert events[2]["event_type"] == "QUERY"


def test_filter_by_event_type(trail):
    trail.append("VAULT_CREATED", actor="o")
    trail.append("QUERY", actor="h")
    trail.append("QUERY", actor="h")
    queries = trail.events(event_type="QUERY")
    assert len(queries) == 2


def test_filter_by_actor(trail):
    trail.append("VAULT_UNLOCKED", actor="owner_1")
    trail.append("QUERY", actor="heir_1")
    owner_events = trail.events(actor="owner_1")
    assert len(owner_events) == 1


def test_length_property(trail):
    assert trail.length == 0
    trail.append("E1", actor="a")
    trail.append("E2", actor="a")
    assert trail.length == 2


def test_tip_hash_changes_on_append(trail):
    h0 = trail.tip_hash
    trail.append("E1", actor="a")
    h1 = trail.tip_hash
    assert h0 != h1


# Implementation note.
# Implementation note.
# Implementation note.

def test_verify_valid_chain(trail):
    trail.append("VAULT_CREATED", actor="o")
    trail.append("ARTIFACT_INGESTED", actor="o", artifact="/doc.pdf")
    result = trail.verify(hmac_key=b"")
    assert result.valid
    assert result.length == 2


def test_verify_with_hmac(trail_hmac):
    trail_hmac.append("VAULT_CREATED", actor="o")
    trail_hmac.append("QUERY", actor="h")
    result = trail_hmac.verify(hmac_key=b"x" * 32)
    assert result.valid
    assert result.hmac_checked


def test_tampered_event_detected(tmp_path):
    """Modifying an event directly in SQLite must break the chain."""
    import sqlite3
    trail = AuditTrail(tmp_path / "t.db", hmac_key=b"")
    trail.append("VAULT_CREATED", actor="owner")
    trail.append("QUERY", actor="heir", detail="original query")

    # Implementation note.
    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("UPDATE audit_events SET detail='TAMPERED' WHERE seq=2")
    conn.commit()
    conn.close()

    # Implementation note.
    trail2 = AuditTrail(tmp_path / "t.db", hmac_key=b"")
    result = trail2.verify(hmac_key=b"")
    assert not result.valid
    assert result.first_invalid_seq == 2


def test_verify_empty_chain(trail):
    result = trail.verify()
    assert result.valid
    assert result.length == 0


# Implementation note.
# Implementation note.
# Implementation note.

def test_chain_continues_across_instances(tmp_path):
    """Sequence and prev_hash must continue correctly after reopening the trail."""
    t1 = AuditTrail(tmp_path / "shared.db", hmac_key=b"")
    t1.append("VAULT_CREATED", actor="o")
    t1.append("ARTIFACT_INGESTED", actor="o")

    # Implementation note.
    t2 = AuditTrail(tmp_path / "shared.db", hmac_key=b"")
    t2.append("QUERY", actor="h")

    result = t2.verify(hmac_key=b"")
    assert result.valid
    assert result.length == 3
    assert t2.events()[-1]["seq"] == 3
