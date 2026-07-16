"""
tests/test_doctor.py
=====================
Doctor: chequeo integral of salud of the legado.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

from legacy.agent.doctor import run_doctor
from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.conditions import AccessPolicy, InactivityCondition

PASS = "pw"


def _make_agent(tmp_path, policy=None) -> LegacyAgent:
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS, policy=policy)
    src = tmp_path / "contract.txt"
    src.write_text("contract of compraventa firmado ante the notario", encoding="utf-8")
    agent.ingest(src)
    agent.archive_artifact(src, PASS)
    return agent


def _check(report, name):
    return next(c for c in report.checks if c.name == name)


# Implementation note.
# Implementation note.
# Implementation note.

def test_healthy_vault_passes_all_checks(tmp_path):
    agent = _make_agent(tmp_path)
    report = run_doctor(agent, passphrase=PASS)
    assert report.ok, report.to_dict()
    names = {c.name for c in report.checks}
    assert names == {"files", "audit_chain", "memory_integrity",
                     "artifact_store", "policy_sanity", "custody",
                     "db_encryption"}


def test_doctor_records_audit_event(tmp_path):
    agent = _make_agent(tmp_path)
    run_doctor(agent, passphrase=PASS)
    assert "DOCTOR_RUN" in [e["event_type"] for e in agent._audit.events()]


def test_doctor_requires_unlocked(tmp_path):
    agent = _make_agent(tmp_path)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        run_doctor(agent)


def test_doctor_without_passphrase_verifies_v2_via_store_key(tmp_path):
    """the artifacts v2 is verifican with the store key of the vault  the
    passphrase already no is necesaria for este check."""
    agent = _make_agent(tmp_path)
    report = run_doctor(agent)          # without a passphrase
    c = _check(report, "artifact_store")
    assert c.ok and "intact" in c.detail


# Implementation note.
# Implementation note.
# Implementation note.

def test_detects_tampered_memory_db(tmp_path):
    agent = _make_agent(tmp_path)
    with sqlite3.connect(tmp_path / "data" / "memory.db") as conn:
        conn.execute("UPDATE memories SET content = 'content forged'")
    report = run_doctor(agent, passphrase=PASS)
    assert not report.ok
    assert not _check(report, "memory_integrity").ok


def test_detects_tampered_audit_chain(tmp_path):
    agent = _make_agent(tmp_path)
    with sqlite3.connect(tmp_path / "data" / "audit.db") as conn:
        conn.execute("UPDATE audit_events SET actor='attacker' WHERE seq=1")
    report = run_doctor(agent, passphrase=PASS)
    assert not report.ok
    assert not _check(report, "audit_chain").ok


def test_detects_corrupted_archived_artifact(tmp_path):
    agent = _make_agent(tmp_path)
    enc = next((tmp_path / "data" / "artifacts").glob("*/*.enc"))
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0xFF
    enc.write_bytes(bytes(raw))
    report = run_doctor(agent, passphrase=PASS)
    assert not report.ok
    assert not _check(report, "artifact_store").ok


# Implementation note.
# Implementation note.
# Implementation note.

def test_detects_future_last_activity(tmp_path):
    future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    policy = AccessPolicy([InactivityCondition(days=30, last_activity_iso=future)])
    agent = _make_agent(tmp_path, policy=policy)
    report = run_doctor(agent, passphrase=PASS)
    assert not report.ok
    c = _check(report, "policy_sanity")
    assert not c.ok and "futuro" in c.detail


def test_db_encryption_check_reflects_state(tmp_path):
    agent = _make_agent(tmp_path)
    # Implementation note.
    c = _check(run_doctor(agent, passphrase=PASS), "db_encryption")
    assert c.ok and "in plaintext" in c.detail
    # Implementation note.
    agent.encrypt_database(PASS)
    c = _check(run_doctor(agent, passphrase=PASS), "db_encryption")
    assert c.ok and "at rest" in c.detail and "in plaintext" not in c.detail


def test_no_policy_is_ok_but_flagged(tmp_path):
    agent = _make_agent(tmp_path)      # without politica
    report = run_doctor(agent, passphrase=PASS)
    c = _check(report, "policy_sanity")
    assert c.ok and "without politica" in c.detail
